# Bentolibc

A CTF utility to identify libc and fetch the address of the wanted functions.

It uses [Postgresql](https://www.postgresql.org/) to optimize the address cache.

This project is created as my Linux C practice project, and inspired by the project with similar function called [libc-database](https://github.com/niklasb/libc-database/).

### Usage

###### Compilation
```bash
git clone https://github.com/astro-angelfish/bentolibc
cmake .
make
```

###### Usage in command line
```bash
./bentolibc download all # Download all libcs
./bentolibc find puts 0x756f7920
./bentolibc dump libc-id
./bentolibc patch /path/to/elf libc-id
./bentolibc one-gaedget libc-id
```

###### Usage in Python
```python
from pwn import *

import sys
sys.path.append("/path/to/bentolibc/python-package") # Bentolibc isn't registered in PIP yet.

import bentolibc
# Some other imports
# ...

sh = remote("114.51.4.191", 9810)
elf = ELF("./rotten-orange")

# Do some leaks
# ...

puts_addr = u64(sh.recv(8).ljust(8, b'\0'))
libc = bentolibc.find("puts", puts_addr)
system_addr = libc.dump("system")
binsh_addr = libc.find("/bin/sh")
onegadgets = libc.one_gadgets()

# Do some exploits
# ...

sh.interactive()
```

### License

This project is licensed user [LGPL v3.0](LICENSE).
