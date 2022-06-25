echo "singer 1"
grep "verify                                   result=" signer.1.log |awk -F "=" '{print $2}'|awk '{print $1}'|sort -n|uniq -c
echo "singer 2"
grep "verify                                   result=" signer.2.log |awk -F "=" '{print $2}'|awk '{print $1}'|sort -n|uniq -c
echo singer 3
grep "verify                                   result=" signer.3.log |awk -F "=" '{print $2}'|awk '{print $1}'|sort -n|uniq -c
