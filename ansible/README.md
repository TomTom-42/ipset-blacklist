# Deploy ipset blocklist

1. Edit hosts file.
2. Edit vars in deploy.yaml

Then run  
```sh
ansible-playbook -i hosts deploy.yaml --limit server1
```
