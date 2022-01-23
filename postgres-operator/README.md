Show user password
export PGPASSWORD=$(kubectl get secret -n pgsql-infra postgres.fenrir-db.credentials.postgresql.acid.zalan.do -o 'jsonpath={.data.password}' | base64 -d)

Format: 
-n <namespace> <pgsql_username>.<team_name>-<cluster_name>.credentials.postgresql.acid.zalan.do