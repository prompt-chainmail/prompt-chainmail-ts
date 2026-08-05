import { describe, it, expect } from "vitest";
import { PromptChainmail } from "../../index";
import { sqlInjection } from "./sql-injection";
import { SecurityFlags } from "../rivets.types";

const SQL_INJECTION_TESTS = {
  positive: {
    unionSelect: "1' UNION SELECT password FROM users--",
    booleanBlind: "1' OR 1=1--",
    timeBlind: "1'; WAITFOR DELAY '00:00:05'--",
    stackedQueries: "'; DROP TABLE users; --",
    informationSchema:
      "1' UNION SELECT table_name FROM information_schema.tables--",
    systemFunctions: "1' UNION SELECT @@VERSION--",
    fileOperations: "1' UNION SELECT LOAD_FILE('/etc/passwd')--",
    errorBased:
      "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users),0x7e))--",
    hexEncoded: "1' UNION SELECT 0x61646d696e--",
    commentEvasion: "1'/*!50000UNION*/SELECT password FROM users--",
  },
  negative: {
    normalQuery: "Please help me find products in the electronics category",
    legitimateComparison: "Find users where age > 18 and status = 'active'",
    businessLogic: "Please reduce the inventory quantity by 1 for product 123",
    reportQuery: "Generate a report showing sales data for the last quarter",
    searchQuery: "Search for products containing the word 'laptop'",
    joinQuery: "Show customer orders with their shipping addresses",
    aggregateQuery: "Calculate the average price of products in each category",
    dateQuery: "Find orders placed between January 1st and March 31st",
    sortQuery: "List all employees sorted by their hire date",
    countQuery: "Count the number of active users in the system",
  },
};

describe("sqlInjection()", () => {
  describe.each(Object.entries(SQL_INJECTION_TESTS.positive))(
    "Positive cases - should detect SQL injection: %s",
    (testName, sqlPayload) => {
      it(`should detect ${testName}`, async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(sqlPayload);

        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
        expect(result.context.metadata.sql_pattern).toBeDefined();
      });
    }
  );

  describe.each(Object.entries(SQL_INJECTION_TESTS.negative))(
    "Negative cases - should NOT detect SQL injection: %s",
    (testName, legitimateQuery) => {
      it(`should not detect ${testName}`, async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(legitimateQuery);

        expect(result.context.flags).not.toContain(SecurityFlags.SQL_INJECTION);
        expect(result.context.metadata.sql_pattern).toBeUndefined();
      });
    }
  );

  describe("UNION-based attacks", () => {
    it("should detect UNION ALL SELECT", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION ALL SELECT password FROM users--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect UNION DISTINCT SELECT", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION DISTINCT SELECT * FROM admin--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect basic UNION SELECT", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT username, password FROM users--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Stacked queries and dangerous statements", () => {
    it("should detect DROP TABLE", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("'; DROP TABLE users; --");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect TRUNCATE TABLE", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("'; TRUNCATE TABLE logs; --");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect CREATE TABLE", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "'; CREATE TABLE backdoor (id INT); --"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect ALTER USER", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "'; ALTER USER admin SET PASSWORD 'hacked'; --"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect stacked INSERT", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "'; INSERT INTO users VALUES('hacker','pass'); --"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect GRANT privileges", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "'; GRANT ALL ON *.* TO 'hacker'@'%'; --"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("DDL/DML with context", () => {
    it("should detect SELECT FROM with context", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "SELECT password FROM users WHERE id=1"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect INSERT INTO", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "INSERT INTO logs VALUES('malicious')"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect DELETE FROM", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "DELETE FROM users WHERE role='admin'"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect UPDATE SET", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "UPDATE users SET password='hacked' WHERE id=1"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Boolean-based blind SQL injection", () => {
    it("should detect OR 1=1", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1' OR 1=1--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect AND 1=1", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1' AND 1=1--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect OR true", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1' OR true--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect numeric comparison", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1' AND 5>4--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect string comparison", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1' OR 'a'='a'--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Time-based blind SQL injection", () => {
    it("should detect WAITFOR DELAY", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1'; WAITFOR DELAY '00:00:05'--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect BENCHMARK", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND BENCHMARK(5000000,MD5(1))--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect SLEEP", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1' AND SLEEP(5)--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect PG_SLEEP", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1'; SELECT PG_SLEEP(5)--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect DBMS_LOCK.SLEEP", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1' AND DBMS_LOCK.SLEEP(5)=0--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Stored procedures and system commands", () => {
    it("should detect EXEC with parentheses", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("'; EXEC('DROP TABLE users')--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect EXECUTE with space", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "'; EXECUTE sp_addlogin 'hacker'--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect XP_CMDSHELL", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("'; EXEC XP_CMDSHELL('dir')--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect SP_OACREATE", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "'; EXEC SP_OACREATE 'Shell.Application'--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect OPENROWSET", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "SELECT * FROM OPENROWSET('SQLOLEDB','server';'uid';'pwd','SELECT 1')"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Information gathering", () => {
    it("should detect INFORMATION_SCHEMA.TABLES", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT table_name FROM information_schema.tables--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect INFORMATION_SCHEMA.COLUMNS", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT column_name FROM information_schema.columns--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect SYSOBJECTS", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT name FROM sysobjects--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect MYSQL.USER", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT user FROM mysql.user--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect PG_TABLES", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT tablename FROM pg_tables--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("File operations", () => {
    it("should detect LOAD_FILE", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT LOAD_FILE('/etc/passwd')--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect INTO OUTFILE", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT 'shell' INTO OUTFILE '/var/www/shell.php'--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect INTO DUMPFILE", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b27636d64275d293b203f3e INTO DUMPFILE '/var/www/shell.php'--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("String manipulation functions", () => {
    it("should detect CHAR function", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND ASCII(SUBSTRING(password,1,1))=CHAR(97)--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect CONCAT function", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT CONCAT(username,':',password) FROM users--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect SUBSTRING function", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND SUBSTRING(password,1,1)='a'--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect ASCII function", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND ASCII(SUBSTRING(password,1,1))>64--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect HEX function", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT HEX(password) FROM users--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect LENGTH comparison", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1' AND LENGTH(password)>5--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Encoding/Decoding functions", () => {
    it("should detect CAST function", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND CAST(password AS VARCHAR)='admin'--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect CONVERT function", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND CONVERT(password, CHAR)='test'--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Error-based injection patterns", () => {
    it("should detect EXTRACTVALUE", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1),0x7e))--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect UPDATEXML", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1),0x7e),1)--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect EXP overflow", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND EXP(~(SELECT * FROM (SELECT password FROM users)x))--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("SQL comments and operators", () => {
    it("should detect MySQL version comment", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1'/*!50000UNION*/SELECT password FROM users--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect comment with plus", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1'-- +");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect semicolon comment", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1'; --");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect pipe operator", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1'||'admin'");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Hexadecimal values", () => {
    it("should detect hex values", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect("1' UNION SELECT 0x61646d696e--");
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect CHAR with hex", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' AND password=CHAR(0x61646d696e)--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Advanced SQL syntax", () => {
    it("should detect WITH clause", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' WITH cte AS (SELECT password FROM users) SELECT * FROM cte--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect CURSOR", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1'; DECLARE cursor1 CURSOR IS SELECT password FROM users--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect FOR XML PATH", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT password FROM users FOR XML PATH('')--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });

    it("should detect PIVOT", async () => {
      const chainmail = new PromptChainmail().forge(sqlInjection());
      const result = await chainmail.protect(
        "1' UNION SELECT * FROM (SELECT role, password FROM users) PIVOT(MAX(password) FOR role IN ('admin'))--"
      );
      expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(true);
    });
  });

  describe("Database-specific patterns", () => {
    describe("Oracle specific", () => {
      it("should detect DUAL table", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(
          "1' UNION SELECT password FROM users UNION SELECT 'test' FROM dual--"
        );
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });

      it("should detect SYS.USER_TABLES", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(
          "1' UNION SELECT table_name FROM sys.user_tables--"
        );
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });

      it("should detect UTL_FILE", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(
          "1'; SELECT UTL_FILE.GET_LINE() FROM dual--"
        );
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });
    });

    describe("SQL Server specific", () => {
      it("should detect @@VERSION", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect("1' UNION SELECT @@VERSION--");
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });

      it("should detect @@SERVERNAME", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(
          "1' UNION SELECT @@SERVERNAME--"
        );
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });

      it("should detect HAS_DBACCESS", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(
          "1' AND HAS_DBACCESS('master')=1--"
        );
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });
    });

    describe("MySQL specific", () => {
      it("should detect VERSION function", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect("1' UNION SELECT VERSION()--");
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });

      it("should detect USER function", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect("1' UNION SELECT USER()--");
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });

      it("should detect DATABASE function", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect("1' UNION SELECT DATABASE()--");
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });
    });

    describe("PostgreSQL specific", () => {
      it("should detect CURRENT_DATABASE", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(
          "1' UNION SELECT CURRENT_DATABASE()--"
        );
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });

      it("should detect CURRENT_USER", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(
          "1' UNION SELECT CURRENT_USER--"
        );
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });

      it("should detect PG_READ_FILE", async () => {
        const chainmail = new PromptChainmail().forge(sqlInjection());
        const result = await chainmail.protect(
          "1' UNION SELECT PG_READ_FILE('/etc/passwd')--"
        );
        expect(result.context.flags.has(SecurityFlags.SQL_INJECTION)).toBe(
          true
        );
      });
    });
  });
});
