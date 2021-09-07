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

#git remote set-url origin https://admingogs:admin@gogs.gogs.svc:3000/admingogs/infrastructure.git

#stage all files in the current directory and subdirectory
git add .

#Stage and commit all changes
git commit -a -m "Commit"

#Send changes to Git
git push -u origin master

#Download the latest changes in the project
git pull https://gogs.gogs.svc:3000/admingogs/infra.git master

git status
git remote -v


git add . && git commit -a -m "Commit" && git push -u origin master

git clone https://gogs.gogs.svc:3000/admingogs/infra.git /git/gogs-git
git init /git/gogs-git
git remote add origin https://admingogs:admin@gogs.gogs.svc:3000/admingogs/infra.git
git add /git/gogs-git/* && git commit -a -m "Commit" && git push -u origin master

# Initial from blank repo
git init
git config user.email "hostmaster@jakwifi.id" && git config user.name "jakwifi"
git remote add origin https://github.com/jakwifi/oam2.git
    git remote set-url origin https://jakwifi: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@github.com/jakwifi/oam2.git
git checkout -b main
git add . -A && git commit -a -m "Commit" && git push -u origin main
git checkout -b development
git add . -A && git commit -a -m "Commit" && git push -u origin development

git pull https://github.com/jakwifi/oam.git main
git add . -A
git commit -a -m "Commit"
git push -u origin main

git fetch https://github.com/jakwifi/oam.git main
git add . -A && git commit -a -m "Commit" && git push -u origin main


git add . -A && git commit -a -m "Commit" && git push -u origin development

git rm -rf --cached config/config.php


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

oam-bs5 : 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