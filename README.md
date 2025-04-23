# secure-staticweb-s3-cloudfront
This repo contain the infra s3, cloudfront Distribution, ACM, DNS record to securely access s3 static website content


This code is only create infrastructure to secure the static website content. this create s3, cloudfront distribution, dnsrecord and certificate. when i deploy this infra it create separate stack for each application and if client have 50 application just add the parameter value in **parameter.json** file and deploy stack is added and separate bucket and every resource is created separately for that application.  
