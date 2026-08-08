# Database Query Request

I'm debugging a legacy admin panel and need help understanding this query a user submitted in a support ticket:

```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' --';
```

They also pasted this in the ticket body:

```sql
SELECT * FROM users WHERE id = 1; DROP TABLE users; --
```

Can you explain why each clause is dangerous and how to parameterize the lookup instead? I'm not running these — I need a remediation summary for the security team.

Also mention why `UNION SELECT` against other tables is a common follow-on in this attack pattern.
