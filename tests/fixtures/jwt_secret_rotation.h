#pragma once

// Independent fixtures: Python stdlib hmac/hashlib, compact JSON and unpadded
// urlsafe_b64encode. Public test keys only; exp=4102444800 (2100-01-01).
namespace jwt_secret_rotation_fixture {
inline constexpr char kCurrentSecret[] =
    "current-cccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
inline constexpr char kPreviousSecret[] =
    "previouspppppppppppppppppppppppppppppppppppppppppppppppppppppppp";
inline constexpr char kUnknownSecret[] =
    "unknown-uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu";
struct Tokens {
    const char* algorithm;
    const char* current;
    const char* previous;
    const char* unknown;
    const char* expired;
    const char* previousExpired;
    const char* future;
    const char* wrongIssuer;
    const char* wrongAudience;
    const char* missingSubject;
    const char* missingScope;
    const char* wrongAlgorithm;
    const char* shortKey;
    const char* emptyKey;
    const char* duplicateClaims;
    const char* criticalHeader;
};
inline constexpr Tokens kTokens[] = {
    {
        "HS256",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.NTfTaR22nV-W9LFgq6vko8wZZUaEjYZQqg4uY7FCDj0",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.VhjLRqsCOTtCctwpdPedarO_pUyaRE3v-OiiVsJAneA",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.E2Fqcm991bWrO3Ro9lMqAX7eUV6Q2peOVMExfKiAE4s",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "EsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.-uccwKdgctcv0IoLRoA2VcHK4W5Aaw5Y29THD6Btoco",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "EsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.HNp9sJ8HKJTdYF2SCfEbnNWgOWmWK6_W6jdby7f19RU",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQiLCJuYmYiOjQxMDI0NDQ3OTl9.XIWsSVl2sUIEy-"
        "utUBtDlP4TQzsxKHibU7sZH2fU4iQ",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL290aGVyLmV4YW1wbGUiLCJhdWQiOiJvcmRlcnMiLCJzdWIiOiJhbGljZSIsImV4cCI6ND"
        "EwMjQ0NDgwMCwic2NvcGUiOiJvcmRlcnMucmVhZCJ9.iMhVDWgyz0y-2n9Df2P8JgUcFwl8EUvDiwerjoffQxs",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3RoZXIiLCJzdWIiOiJhbGljZSIsImV4cCI6ND"
        "EwMjQ0NDgwMCwic2NvcGUiOiJvcmRlcnMucmVhZCJ9.0u5Om-pYWD4epAgAT8x7gZuXoX3v2dLHdllEuYQfhC8",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwiZXhwIjo0MTAyNDQ0ODAwLCJzY2"
        "9wZSI6Im9yZGVycy5yZWFkIn0.oqcIWgx68fWtzN9rPvH7sh_JTQx1XT9RWhJBJVpRl6c",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDB9.4H2qWyr8io08ZntDeJCfS2_kfHkWAHPs0d3ftofvOV8",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.e4YTVz6GsWtCBmAqRiPctckiVAcX-"
        "qM377rkOWey5EciollP3YbIUT3fkaUa5iZ3",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.qbEll69Txb_fecInYvPyX8WBR6TTvs9Y3ML0S5J007M",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.M8fHAa6KiGcSzL-hhizSh5M6VfoeapktcXemn0gFQDg",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiaXNzIjoiaHR0cHM6Ly9vdGhlci5leGFtcGxlIiwiYXVkIj"
        "oib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ."
        "hPrP543EJu6NhjXq1Zhs5H7hdpo7EQjRSBu1tbGCJiU",
        "eyJhbGciOiJIUzI1NiIsImNyaXQiOlsiZXh0ZW5zaW9uIl0sImV4dGVuc2lvbiI6dHJ1ZX0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.edVpnoNSIdg-64shvaamqBrL7LpzNccC71ljMuTx5kQ",
    },
    {
        "HS384",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.e4YTVz6GsWtCBmAqRiPctckiVAcX-"
        "qM377rkOWey5EciollP3YbIUT3fkaUa5iZ3",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.naw8S9yykKuhu_wxpQFEF5bI7KxifgNY_"
        "JC3YybEZMlshEn7H-ryZA7Yk7CVONbx",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ."
        "4doiLNNPvRg1Bl9qulpCbj4jLPV256UjC8aLzUKmwI07nSCiQtIazaQ1Q13l2s7e",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "EsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.qnu7jLzVY80dzIaAMoMGbN9Dtf7Rz3pPsTkYeMlOQzls_"
        "RPNU3eE3l7MIdh_4Ypp",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "EsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.BjckYq1UTyRgtUmg2USiAKGE9qBP-bf74CRze18lv4InzYwx7SozaC-"
        "79ONzab7P",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQiLCJuYmYiOjQxMDI0NDQ3OTl9.BP0dv4tG8YOQ-"
        "Kka8agPOdzPdiwN-tHxC4_uAMfuu47B1E6w1wJm4UoCmUfrf0qP",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL290aGVyLmV4YW1wbGUiLCJhdWQiOiJvcmRlcnMiLCJzdWIiOiJhbGljZSIsImV4cCI6ND"
        "EwMjQ0NDgwMCwic2NvcGUiOiJvcmRlcnMucmVhZCJ9.xXTR247L6He6KQlwTgex1nvsl2FgmD9o3nyzzNJpB0i-"
        "6RCNR5bX7hZVu2-wjLTb",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3RoZXIiLCJzdWIiOiJhbGljZSIsImV4cCI6ND"
        "EwMjQ0NDgwMCwic2NvcGUiOiJvcmRlcnMucmVhZCJ9.-"
        "8H6mNBTWhE4Whw3tndtlultgp142XWtEqdegKJ24ROetHniaYwITRGkBFccFp0e",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwiZXhwIjo0MTAyNDQ0ODAwLCJzY2"
        "9wZSI6Im9yZGVycy5yZWFkIn0.nfJrBKcX0OqFf2r9k-Eg6XSqC0Nh4cP9JLVFn4fk5PxVj9g_6wBAKr7vLGBev-"
        "y6",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDB9.VkgPdZmBd5gsOapJNqzMUO7JMDIgHd5m40ygYJk0ufms5Vo6e624ThanIP5cm6GC",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.NTfTaR22nV-W9LFgq6vko8wZZUaEjYZQqg4uY7FCDj0",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.KJrQwTn1DkvEqB_QbtqetlQD1WUb3yImPjxld-"
        "YqFxJjyNxDYbJep1uGlmEU3Cpc",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.KDI4y3uT_ck2pIlmDN0S9W4uCg-"
        "YOgNTPdc9KxqTBH3Y1Om_V1FUZ2Vgl28D5blo",
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiaXNzIjoiaHR0cHM6Ly9vdGhlci5leGFtcGxlIiwiYXVkIj"
        "oib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ."
        "D7Pi7nAr6SKBK9ZVgRKhPbqMQE4rb2C8bWMXd7bq6Ov7VI2I83o5jd_hkeE9Y6NL",
        "eyJhbGciOiJIUzM4NCIsImNyaXQiOlsiZXh0ZW5zaW9uIl0sImV4dGVuc2lvbiI6dHJ1ZX0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.VtM83UNdYnlDNXwjJ1qF_"
        "Y7MZCkdMV05Bdh5ygvLwOwVozdRtPGm173em_rgq-nc",
    },
    {
        "HS512",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ."
        "VMNht4LgVw4pYSzD6GBelDHE5Z5M1N92dhBbLfckmROOroNf1ze7Yenf8HI0dpGvftB7sckpjWJCH4C6cfjv0A",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ."
        "aWAtkbszvm02sNDaFBWrPR0XYfhOm6gdhKSiYfc5fCEYsaleRV7aEnees8LHwl0f7Rd7C32aK29ew0KyxgBJbg",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.qpLzoza0dsLh2UF7q_stTkHIKCqP_"
        "HntNP7ewbXXjVVUyN1tM4IKK4yvm7qTFFFWwmk54N2h4BaWFiCh7E8kFg",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "EsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.kYyPiVJDwsBMatkqmcNzIXkf47FLkv4HaTLsdg0-"
        "YS3Tmvo46JRwQUDkFjc78LflqUAYm-jCxcB-sJh_1Loo2g",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "EsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.IXoijEbPepkn04dBz_qoGl49BT5s9hdQWnTUJdImIA0aV98a_hxvim_"
        "Pvky2iBCN_mF0JbmBsnkFLdNCqM_ygw",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQiLCJuYmYiOjQxMDI0NDQ3OTl9.wR3aQ2tT7mrZ3Z7FO-P-_"
        "ZcHFTe7LJZEWYnkkRoVaoxNnZs_lMO-Th8BfgdTC6B7xdOKgSZYpgRu_4uqrUOC3Q",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL290aGVyLmV4YW1wbGUiLCJhdWQiOiJvcmRlcnMiLCJzdWIiOiJhbGljZSIsImV4cCI6ND"
        "EwMjQ0NDgwMCwic2NvcGUiOiJvcmRlcnMucmVhZCJ9."
        "KVD5k06HPl8zh1MuSVrCVvflC3XNdt7kt57Bs3hR5mHryzkn1HMmHuFdU2IRrOsLPNLdiqLHJkXNJVpUzbo19w",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3RoZXIiLCJzdWIiOiJhbGljZSIsImV4cCI6ND"
        "EwMjQ0NDgwMCwic2NvcGUiOiJvcmRlcnMucmVhZCJ9.Nhq6A07_lgaY_EelyJcRAxap-"
        "uTwAkxrYe8UMvHkhE4OrDzJnhQyQlNLF6LPNDCdTVUowiHH8buoBeGFwJD8gA",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwiZXhwIjo0MTAyNDQ0ODAwLCJzY2"
        "9wZSI6Im9yZGVycy5yZWFkIn0."
        "ULkkr0FuWRcugAxYRz0m1jsEGh1aMXNBtjdfZqTJkTCdjjhyR6f7QNRBj0uGHe9cmpWMNYpFJNtS_gWSBSXR2A",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDB9.WQzk46o2tRidjK1aDkuZevdOOoLe7QQm4cb-"
        "cuHdKQQZhVn3iB7SrbxLAQsYNzxjX1YWmn3iFv32Z8QKxXWxlw",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.NTfTaR22nV-W9LFgq6vko8wZZUaEjYZQqg4uY7FCDj0",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ._NMvfule3EgmckmZE-"
        "GmepBP40aJIttFwIJAo8trt6Td75sLCqqGAJvFHyyTzK_qjXzYt_vH-PARVkDrckfnGQ",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ.W7nAI-"
        "jCytQcdJx03sFDsifLuaqLZioVPXzACFTt6YPYMEM_jTNknotb47G0uzntUUZREu_GsNBq4gwafQzAVQ",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InVudHJ1c3RlZC10b2tlbi1oaW50In0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiaXNzIjoiaHR0cHM6Ly9vdGhlci5leGFtcGxlIiwiYXVkIj"
        "oib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOjQxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ."
        "b5nVS_Hs2nD1J0W0YV76bxFGfO0fw1b6OJD-gJezVHXcF0xxqffzH0m5FJNcq9-sVPkQxhDQXX4UJevw1qy3vg",
        "eyJhbGciOiJIUzUxMiIsImNyaXQiOlsiZXh0ZW5zaW9uIl0sImV4dGVuc2lvbiI6dHJ1ZX0."
        "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiYXVkIjoib3JkZXJzIiwic3ViIjoiYWxpY2UiLCJleHAiOj"
        "QxMDI0NDQ4MDAsInNjb3BlIjoib3JkZXJzLnJlYWQifQ."
        "x7ZNTLPG5sHPcOuni5keyGXQb265QQxE6iuUvHCgEYnxZbpac7wxU64hojQMnjWbrX9b8of04vchKeS_kboqjQ",
    },
};
}  // namespace jwt_secret_rotation_fixture
