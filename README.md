# macrandrd

### Just a tiny OpenBSD daemon to change periodically MAC addresses

**OpenBSD** MAC address randomization daemon

#### Installation procedure
```
tar -xvzf macrandrd-{VERSION}.tar.gz
cd macrandrd-{VERSION}
make all
doas make install
```
#### Uninstall procedure

```
doas make clean
```

#### Manual page

```
man macrandrd
```

#### daemon handlers

```
doas rcctl enable macrandrd
doas rcctl start macrandrd
```

