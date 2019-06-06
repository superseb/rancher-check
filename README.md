# rancher-check

Checks connectivity (HTTPS/DNS/certificates) to a Rancher 2.0 setup by using a server-url (`https://rancher.yourdomain.com`)

Also see the Golang based tool: https://github.com/superseb/ranchercheck

## How to use

### Shell

```
bash rancher-check.sh https://rancher.yourdomain.com
```

### Docker

```
docker run superseb/rancher-check https://rancher.yourdomain.com
```
