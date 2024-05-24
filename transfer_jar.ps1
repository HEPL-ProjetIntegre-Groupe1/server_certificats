cp .\out\artifacts\server_certificats_jar\server_certificats.jar .
zip -d server_certificats.jar 'META-INF/*.SF' 'META-INF/*.RSA'
ssh user@10.0.0.13 'cd server_certificats && git pull'