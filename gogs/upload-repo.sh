#Configure git The username and email address should match the ones you use in Git
git config --global user.email "admin@admin.org" && git config --global user.name "Admin Gogs"

#Enable credentials storage globally
git config --global credential.helper store

#Accept self signed certificate
git config --global http.sslVerify false

#Convert a local directory into a repository
git init

#Add remote
git remote add origin https://gogs.gogs.svc:3000/admingogs/infrastructure.git

#stage all files in the current directory and subdirectory
git add .

#Stage and commit all changes
git commit -a -m "Commit"

#Send changes to Git
git push -u origin master

git status