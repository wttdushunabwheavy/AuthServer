#include <drogon/drogon.h>
#include <libpq-fe.h>
#include <argon2.h>

#include <windows.h>
#include <bcrypt.h>

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <array>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>

namespace
{
    // Loaded once at startup from db_password.txt beside the executable.
    std::string DB_PASSWORD;

    std::filesystem::path executableDirectory()
    {
        std::wstring path(MAX_PATH, L'\0');
        const DWORD length = GetModuleFileNameW(
            nullptr, path.data(), static_cast<DWORD>(path.size()));

        if (length == 0 || length >= path.size())
            return std::filesystem::current_path();

        path.resize(length);
        return std::filesystem::path(path).parent_path();
    }

    bool loadDatabasePassword()
    {
        const auto passwordFile = executableDirectory() / L"db_password.txt";
        std::ifstream file(passwordFile, std::ios::binary);

        if (!file)
        {
            std::cerr << "Could not open db_password.txt beside the executable.\n";
            return false;
        }

        if (!std::getline(file, DB_PASSWORD))
        {
            std::cerr << "Could not read db_password.txt.\n";
            return false;
        }

        // Remove the carriage return if the file uses Windows CRLF line endings.
        if (!DB_PASSWORD.empty() && DB_PASSWORD.back() == '\r')
            DB_PASSWORD.pop_back();

        if (DB_PASSWORD.empty())
        {
            std::cerr << "db_password.txt is empty.\n";
            return false;
        }

        return true;
    }

    constexpr std::size_t SALT_SIZE = 16;
    constexpr std::size_t HASH_SIZE = 32;
    constexpr std::size_t TOKEN_SIZE = 32;

    using DbConnection =
        std::unique_ptr<PGconn, decltype(&PQfinish)>;

    using DbResult =
        std::unique_ptr<PGresult, decltype(&PQclear)>;

    DbConnection connectDatabase()
    {
        const char* keywords[] = {
            "host", "port", "dbname", "user", "password", nullptr
        };
        const char* values[] = {
            "localhost", "5432", "authserver", "postgres",
            DB_PASSWORD.c_str(), nullptr
        };

        return DbConnection(
            PQconnectdbParams(keywords, values, 0), PQfinish);
    }

    drogon::HttpResponsePtr jsonError(
        drogon::HttpStatusCode status,
        const std::string& message)
    {
        Json::Value json;
        json["error"] = message;

        auto response = drogon::HttpResponse::newHttpJsonResponse(json);
        response->setStatusCode(status);
        return response;
    }

    bool randomBytes(unsigned char* buffer, std::size_t size)
    {
        return BCryptGenRandom(
            nullptr,
            buffer,
            static_cast<ULONG>(size),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    std::string toHex(
        const unsigned char* data,
        std::size_t size)
    {
        std::ostringstream output;
        output << std::hex << std::setfill('0');

        for (std::size_t i = 0; i < size; ++i)
        {
            output << std::setw(2)
                   << static_cast<unsigned int>(data[i]);
        }

        return output.str();
    }

    bool sha256(
        const std::string& input,
        std::string& output)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD objectSize = 0;
        DWORD resultSize = 0;
        bool success = false;

        std::vector<unsigned char> object;
        std::array<unsigned char, 32> digest{};

        if (BCryptOpenAlgorithmProvider(
                &algorithm,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                0) != 0)
        {
            return false;
        }

        if (BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&objectSize),
                sizeof(objectSize),
                &resultSize,
                0) != 0)
        {
            goto cleanup;
        }

        object.resize(objectSize);

        if (BCryptCreateHash(
                algorithm,
                &hash,
                object.data(),
                objectSize,
                nullptr,
                0,
                0) != 0)
        {
            goto cleanup;
        }

        if (BCryptHashData(
                hash,
                reinterpret_cast<PUCHAR>(
                    const_cast<char*>(input.data())),
                static_cast<ULONG>(input.size()),
                0) != 0)
        {
            goto cleanup;
        }

        if (BCryptFinishHash(
                hash,
                digest.data(),
                static_cast<ULONG>(digest.size()),
                0) != 0)
        {
            goto cleanup;
        }

        output = toHex(digest.data(), digest.size());
        success = true;

    cleanup:
        if (hash)
            BCryptDestroyHash(hash);

        BCryptCloseAlgorithmProvider(algorithm, 0);
        return success;
    }

    bool hashPassword(
        const std::string& password,
        std::string& encodedHash)
    {
        std::array<unsigned char, SALT_SIZE> salt{};

        if (!randomBytes(salt.data(), salt.size()))
            return false;

        std::array<char, 256> encoded{};

        const int result = argon2id_hash_encoded(
            2,                  // iterations
            19456,              // memory in KiB: 19 MiB
            1,                  // parallelism
            password.data(),
            password.size(),
            salt.data(),
            salt.size(),
            HASH_SIZE,
            encoded.data(),
            encoded.size());

        if (result != ARGON2_OK)
            return false;

        encodedHash = encoded.data();
        return true;
    }

    bool generateToken(std::string& token)
    {
        std::array<unsigned char, TOKEN_SIZE> bytes{};

        if (!randomBytes(bytes.data(), bytes.size()))
            return false;

        token = toHex(bytes.data(), bytes.size());
        return true;
    }

    bool isValidCredentialsInput(
        const Json::Value& json)
    {
        return json.isObject()
            && json.isMember("username")
            && json.isMember("password")
            && json["username"].isString()
            && json["password"].isString();
    }
    
    bool containsOnlyEnglishLettersAndDigits(const std::string& value)
    {
        return !value.empty() &&
            std::all_of(value.begin(), value.end(),
                [](unsigned char c)
                {
                    return (c >= 'A' && c <= 'Z') ||
                           (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9');
                });
    }

    void registerRoutes()
    {
        // Health check.
        drogon::app().registerHandler(
            "/api/status",
            [](const drogon::HttpRequestPtr&,
               std::function<void(const drogon::HttpResponsePtr&)>&& callback)
            {
                Json::Value json;
                json["status"] = "ok";

                callback(
                    drogon::HttpResponse::newHttpJsonResponse(json));
            },
            {drogon::Get}
        );

        // Register a new account.
        drogon::app().registerHandler(
            "/api/register",
            [](const drogon::HttpRequestPtr& req,
               std::function<void(const drogon::HttpResponsePtr&)>&& callback)
            {
                auto json = req->getJsonObject();

                if (!json || !isValidCredentialsInput(*json))
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "Username and password must be strings"));
                    return;
                }

                
                
                const std::string username =
                    (*json)["username"].asString();

                const std::string password =
                    (*json)["password"].asString();

                if (!containsOnlyEnglishLettersAndDigits(username) || !containsOnlyEnglishLettersAndDigits(password))
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "Username and password must contain only English letters and digits"));
                    return;
                }
                
                if (username.empty() || username.size() > 14)
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "Username must contain 1-14 bytes"));
                    return;
                }

                if (password.empty() || password.size() > 14)
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "Password must contain 1-14 bytes"));
                    return;
                }

                std::string passwordHash;

                if (!hashPassword(password, passwordHash))
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Password hashing failed"));
                    return;
                }

                auto db = connectDatabase();

                if (!db || PQstatus(db.get()) != CONNECTION_OK)
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Database connection failed"));
                    return;
                }

                const char* values[] = {
     username.c_str(),
     passwordHash.c_str(),
     "1"
 };
                
 DbResult result(
     PQexecParams(
         db.get(),
         "INSERT INTO accounts (username, password_hash, role_id) "
         "VALUES ($1, $2, $3) RETURNING id",
         3,
         nullptr,
         values,
         nullptr,
         nullptr,
         0),
     PQclear);

                if (!result ||
                    PQresultStatus(result.get()) != PGRES_TUPLES_OK)
                {
                    const char* sqlState = result
                        ? PQresultErrorField(
                            result.get(), PG_DIAG_SQLSTATE)
                        : nullptr;

                    if (sqlState &&
                        std::string(sqlState) == "23505")
                    {
                        callback(jsonError(
                            drogon::k409Conflict,
                            "Username already exists"));
                        return;
                    }

                    std::cerr << "Registration database error";
                    if (result)
                    {
                        const char* errorMessage = PQresultErrorMessage(result.get());
                        const char* state = PQresultErrorField(
                            result.get(), PG_DIAG_SQLSTATE);

                        if (state)
                            std::cerr << " [SQLSTATE " << state << "]";
                        if (errorMessage && *errorMessage)
                            std::cerr << ": " << errorMessage;
                    }
                    else
                    {
                        std::cerr << ": PQexecParams returned a null result";
                    }
                    std::cerr << std::endl;

                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Registration failed"));
                    return;
                }

                Json::Value response;
                response["status"] = "registered";
                response["account_id"] =
                    static_cast<Json::Int64>(
                        std::stoll(PQgetvalue(result.get(), 0, 0)));

                callback(
                    drogon::HttpResponse::newHttpJsonResponse(response));
            },
            {drogon::Post}
        );

        // Login and create a session.
        drogon::app().registerHandler(
            "/api/login",
            [](const drogon::HttpRequestPtr& req,
               std::function<void(const drogon::HttpResponsePtr&)>&& callback)
            {
                auto json = req->getJsonObject();

                if (!json || !isValidCredentialsInput(*json))
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "Invalid request"));
                    return;
                }

                const std::string username =
                    (*json)["username"].asString();

                const std::string password =
                    (*json)["password"].asString();
                
                if (!containsOnlyEnglishLettersAndDigits(username) || !containsOnlyEnglishLettersAndDigits(password))
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "Username and password must contain only English letters and digits"));
                    return;
                }

                if (username.empty() || username.size() > 14 ||
                    password.empty() || password.size() > 14)
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "Invalid request"));
                    return;
                }

                auto db = connectDatabase();

                if (!db || PQstatus(db.get()) != CONNECTION_OK)
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Database connection failed"));
                    return;
                }

                const char* lookupValues[] = {
                    username.c_str()
                };

                DbResult account(
                    PQexecParams(
                        db.get(),
                        "SELECT id, password_hash FROM accounts "
                        "WHERE username = $1",
                        1,
                        nullptr,
                        lookupValues,
                        nullptr,
                        nullptr,
                        0),
                    PQclear);

                if (!account ||
                    PQresultStatus(account.get()) != PGRES_TUPLES_OK)
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Database query failed"));
                    return;
                }

                if (PQntuples(account.get()) != 1)
                {
                    callback(jsonError(
                        drogon::k401Unauthorized,
                        "Invalid username or password"));
                    return;
                }

                const std::string accountId =
                    PQgetvalue(account.get(), 0, 0);

                const std::string storedHash =
                    PQgetvalue(account.get(), 0, 1);

                if (argon2id_verify(
                        storedHash.c_str(),
                        password.data(),
                        password.size()) != ARGON2_OK)
                {
                    callback(jsonError(
                        drogon::k401Unauthorized,
                        "Invalid username or password"));
                    return;
                }

                std::string token;
                std::string tokenHash;

                if (!generateToken(token) ||
                    !sha256(token, tokenHash))
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Token generation failed"));
                    return;
                }

                const char* sessionValues[] = {
                    accountId.c_str(),
                    tokenHash.c_str()
                };

                DbResult session(
                    PQexecParams(
                        db.get(),
                        "INSERT INTO sessions "
                        "(account_id, token_hash, expires_at) "
                        "VALUES ($1, $2, NOW() + INTERVAL '5 minutes')",
                        2,
                        nullptr,
                        sessionValues,
                        nullptr,
                        nullptr,
                        0),
                    PQclear);

                if (!session ||
                    PQresultStatus(session.get()) != PGRES_COMMAND_OK)
                {
                    std::cerr << "Session creation failed\n";

                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Could not create session"));
                    return;
                }

                Json::Value response;
                response["status"] = "ok";
                response["account_id"] =
                    static_cast<Json::Int64>(std::stoll(accountId));
                response["access_token"] = token;
                response["expires_in"] = 300;

                callback(
                    drogon::HttpResponse::newHttpJsonResponse(response));
            },
            {drogon::Post}
            );
            
        // Validate an access token.
        drogon::app().registerHandler(
            "/api/validate",
            [](const drogon::HttpRequestPtr& req,
               std::function<void(const drogon::HttpResponsePtr&)>&& callback)
            {
                auto json = req->getJsonObject();

                if (!json || !json->isObject() ||
                    !json->isMember("access_token") ||
                    !(*json)["access_token"].isString())
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "access_token is required"));
                    return;
                }

                const std::string token =
                    (*json)["access_token"].asString();

                if (token.size() != 64)
                {
                    callback(jsonError(
                        drogon::k401Unauthorized,
                        "Invalid or expired token"));
                    return;
                }

                std::string tokenHash;

                if (!sha256(token, tokenHash))
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Token validation failed"));
                    return;
                }

                auto db = connectDatabase();

                if (!db || PQstatus(db.get()) != CONNECTION_OK)
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Database connection failed"));
                    return;
                }

                const char* values[] = { tokenHash.c_str() };

                DbResult result(
                    PQexecParams(
                        db.get(),
                        "SELECT account_id FROM sessions "
                        "WHERE token_hash = $1 "
                        "AND expires_at > NOW()",
                        1,
                        nullptr,
                        values,
                        nullptr,
                        nullptr,
                        0),
                    PQclear);

                if (!result ||
                    PQresultStatus(result.get()) != PGRES_TUPLES_OK)
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Database query failed"));
                    return;
                }

                if (PQntuples(result.get()) != 1)
                {
                    callback(jsonError(
                        drogon::k401Unauthorized,
                        "Invalid or expired token"));
                    return;
                }

                Json::Value response;
                response["valid"] = true;
                response["account_id"] =
                    static_cast<Json::Int64>(
                        std::stoll(PQgetvalue(result.get(), 0, 0)));

                callback(
                    drogon::HttpResponse::newHttpJsonResponse(response));
            },
            {drogon::Post}
        );

        // Revoke an access token (logout).
        drogon::app().registerHandler(
            "/api/logout",
            [](const drogon::HttpRequestPtr& req,
               std::function<void(const drogon::HttpResponsePtr&)>&& callback)
            {
                auto json = req->getJsonObject();

                if (!json || !json->isObject() ||
                    !json->isMember("access_token") ||
                    !(*json)["access_token"].isString())
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "access_token is required"));
                    return;
                }

                const std::string token =
                    (*json)["access_token"].asString();

                if (token.size() != 64)
                {
                    callback(jsonError(
                        drogon::k401Unauthorized,
                        "Invalid or expired token"));
                    return;
                }

                std::string tokenHash;

                if (!sha256(token, tokenHash))
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Token processing failed"));
                    return;
                }

                auto db = connectDatabase();

                if (!db || PQstatus(db.get()) != CONNECTION_OK)
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Database connection failed"));
                    return;
                }

                const char* values[] = { tokenHash.c_str() };

                DbResult result(
                    PQexecParams(
                        db.get(),
                        "DELETE FROM sessions "
                        "WHERE token_hash = $1 "
                        "RETURNING id",
                        1,
                        nullptr,
                        values,
                        nullptr,
                        nullptr,
                        0),
                    PQclear);

                if (!result ||
                    PQresultStatus(result.get()) != PGRES_TUPLES_OK)
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Could not revoke session"));
                    return;
                }

                if (PQntuples(result.get()) != 1)
                {
                    callback(jsonError(
                        drogon::k401Unauthorized,
                        "Invalid or expired token"));
                    return;
                }

                Json::Value response;
                response["status"] = "logged_out";

                callback(
                    drogon::HttpResponse::newHttpJsonResponse(response));
            },
            {drogon::Post}
        );
        
        // Get character name by account ID (development/testing).
        drogon::app().registerHandler(
            "/api/character",
            [](const drogon::HttpRequestPtr& req,
               std::function<void(const drogon::HttpResponsePtr&)>&& callback)
            {
                const std::string accountId =
                    req->getParameter("account_id");

                // Accept only a positive integer ID.
                if (accountId.empty() ||
                    accountId.size() > 18 ||
                    accountId.find_first_not_of("0123456789") !=
                        std::string::npos ||
                    accountId == "0")
                {
                    callback(jsonError(
                        drogon::k400BadRequest,
                        "Valid account_id is required"));
                    return;
                }

                auto db = connectDatabase();

                if (!db || PQstatus(db.get()) != CONNECTION_OK)
                {
                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Database connection failed"));
                    return;
                }

                const char* values[] = { accountId.c_str() };

                DbResult result(
                    PQexecParams(
                        db.get(),
                        "SELECT name FROM characters "
                        "WHERE account_id = $1::bigint",
                        1,
                        nullptr,
                        values,
                        nullptr,
                        nullptr,
                        0),
                    PQclear);

                if (!result ||
                    PQresultStatus(result.get()) != PGRES_TUPLES_OK)
                {
                    std::cerr << "Character query failed\n";

                    callback(jsonError(
                        drogon::k500InternalServerError,
                        "Character query failed"));
                    return;
                }

                if (PQntuples(result.get()) == 0)
                {
                    callback(jsonError(
                        drogon::k404NotFound,
                        "Character not found"));
                    return;
                }

                Json::Value response;
                response["name"] = PQgetvalue(result.get(), 0, 0);

                callback(
                    drogon::HttpResponse::newHttpJsonResponse(response));
            },
            {drogon::Get}
        );

    }
}

int main()
{
    if (!loadDatabasePassword())
        return 1;

    auto db = connectDatabase();

    if (!db || PQstatus(db.get()) != CONNECTION_OK)
    {
        std::cerr << "Database connection failed:\n";

        if (db)
            std::cerr << PQerrorMessage(db.get());

        std::cerr << '\n';
        return 1;
    }

    std::cout << "Connected to PostgreSQL!\n";

    registerRoutes();

    drogon::app()
        .addListener("0.0.0.0", 8081)
        .run();

    return 0;
}

