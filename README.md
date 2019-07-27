# RailsCookie
## Installation
```bash
python3 -m pip install railscookie
```

## Example
```python
from railscookie import RailsCookie

cookiejar = RailCookie("<<RAILS_SECRECT_KEY_BASE>>")
cookie = cookiejar.loads(b"<<RAILS_ENCODED_COOKIE>>")
cookie["id"] += 1
print(cookiejar.dumps(cookie).decode())
```

## Author
Nao YONASHIRO (@orisano)

## License
MIT
