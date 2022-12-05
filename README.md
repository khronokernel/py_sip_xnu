# py_sip_xnu

Python module for parsing macOS's SIP configuration.

Library returns a SIP object with the following properties:
```
value                    - int  - raw value of SIP configuration (integer)
breakdown                - dict - dictionary holding each SIP key and its value
can_edit_root            - bool - whether SIP allows editing of protected files
can_write_nvram          - bool - whether SIP allows writing to NVRAM
can_load_arbitrary_kexts - bool - whether SIP allows loading of arbitrary kexts
```

If module accessed under Yosemite or earlier, `sip_xnu` will treat SIP as disabled.

## Usage

```python
import py_sip_xnu

sip_config = py_sip_xnu.sip_xnu.get_sip_config()

'''
sip_config = {
    'value': 0,
    'breakdown': {
        'CSR_ALLOW_UNTRUSTED_KEXTS': False,
        'CSR_ALLOW_UNRESTRICTED_FS': False,
        'CSR_ALLOW_TASK_FOR_PID': False,
        'CSR_ALLOW_KERNEL_DEBUGGER': False,
        'CSR_ALLOW_APPLE_INTERNAL': False,
        'CSR_ALLOW_UNRESTRICTED_DTRACE': False,
        'CSR_ALLOW_UNRESTRICTED_NVRAM': False,
        'CSR_ALLOW_DEVICE_CONFIGURATION': False,
        'CSR_ALLOW_ANY_RECOVERY_OS': False,
        'CSR_ALLOW_UNAPPROVED_KEXTS': False,
        'CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE': False,
        'CSR_ALLOW_UNAUTHENTICATED_ROOT': False
    },
    'can_edit_root': False,
    'can_write_nvram': False,
    'can_load_arbitrary_kexts': False
}
'''
```

## License

BSD 3-Clause License

Copyright (c) 2022, Mykola Grymalyuk