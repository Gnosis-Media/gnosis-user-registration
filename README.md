# gnosis-user-registration

![alt text](image.png)


DB is working well

How to use

pip install -r requirements.txt flask run

Window Invoke-WebRequest -Uri http://127.0.0.1:5000/api/register -Method POST -Body '{"username": "realuser", "email": "realuser@example.com", "password": "RealPassword123"}' ` -ContentType "application/json"

Mac curl -X POST http://127.0.0.1:5000/api/register
-H "Content-Type: application/json"
-d '{"username": "realuser", "email": "realuser@example.com", "password": "RealPassword123"}'

