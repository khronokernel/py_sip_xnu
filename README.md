# py_sip_xnu

Python module for parsing macOS's SIP configuration.

Library returns a SIP object with the following properties:
```
value                    - int     - raw value of SIP configuration (integer)
breakdown                - dict    - dictionary holding each SIP key and its value
can_edit_root            - boolean - whether SIP allows editing of protected files
can_write_nvram          - boolean - whether SIP allows writing to NVRAM
can_load_arbitrary_kexts - boolean - whether SIP allows loading of arbitrary kexts
```

## Usage

```python
import py_sip_xnu

sip_config = py_sip_xnu.sip_xnu.get_sip_config()

print(sip_config.value)
```