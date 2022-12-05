# py_sip_xnu

Python module for querying SIP status on XNU-based systems (primarily macOS).

Library returns a SIP object with the following properties:
```
value                    - int    - raw value of SIP configuration
breakdown                - object - holds each SIP key and its value
can_edit_root            - bool   - whether SIP allows editing of protected files
can_write_nvram          - bool   - whether SIP allows writing to NVRAM
can_load_arbitrary_kexts - bool   - whether SIP allows loading of arbitrary kexts
```

If module accessed under Yosemite or earlier, `sip_xnu` will treat SIP as disabled.

Project currently synced against macOS 13.0 (XNU 8792.41.9). Based off of [pudquick's concept](https://gist.github.com/pudquick/8b320be960e1654b908b10346272326b).

Python validated against 2.7 and 3.9.

## Background

System Integrity Protection, generally abbreviated as SIP, is a security feature introduced in OS X El Capitan. Primary purpose of this setting was to control access to sensitive operations such as kernel extension loading, protected file write, task tracking, etc. SIP is part of the XNU kernel, and is a cumulation of several kernel flags into the CSR bitmask seen as SIP configuration.

Source for SIP configuration can be found in Apple's [csr.h](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.41.9/bsd/sys/csr.h), and parsing logic from [csr.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.41.9/libsyscall/wrappers/csr.c).


## Installation

pip-based:
```sh
pip3 install py_sip_xnu
```

Manual:
```sh
python3 setup.py install
```

## Usage

Invocation:
```python
import py_sip_xnu

sip_config = py_sip_xnu.SipXnu().get_sip_status()

'''
sip_config = {
    'value': 0,
    'breakdown': {
        'csr_allow_untrusted_kexts': False,
        'csr_allow_unrestricted_fs': False,
        'csr_allow_task_for_pid': False,
        'csr_allow_kernel_debugger': False,
        'csr_allow_apple_internal': False,
        'csr_allow_unrestricted_dtrace': False,
        'csr_allow_unrestricted_nvram': False,
        'csr_allow_device_configuration': False,
        'csr_allow_any_recovery_os': False,
        'csr_allow_unapproved_kexts': False,
        'csr_allow_executable_policy_override': False,
        'csr_allow_unauthenticated_root': False
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