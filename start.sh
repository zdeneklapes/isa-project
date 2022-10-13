#!/bin/bash
#set -x # log

RM="rm -rfd"
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'

AUTHOR='Zdenek Lapes'
EMAIL='lapes.zdenek@gmail.com'

PROJECT_NAME='pawnshop'

# Utils
function error_exit() {
    printf "${RED}ERROR: $1${NC}\n"
    usage
    exit 1
}

# Docker
function build_up_docker() {
    docker-compose -f docker-compose.yaml up --build
}

function install_docker_deploy() {
    docker-compose up --build -d -f docker-compose-build.yml
}

function docker_show_ipaddress() {
    for docker_container in $(docker ps -aq); do
        CMD1="$(docker ps -a | grep "$docker_container" | grep --invert-match "Exited\|Created" | awk '{print $2}'): "
        if [ "$CMD1" != ": " ]; then
            printf "$CMD1"
            printf "$(docker inspect ${docker_container} | grep "IPAddress" | tail -n 1)\n"
        fi
    done
}

function rm_docker_images_volumes() {
    docker stop $(docker ps -aq)
    docker system prune -a -f
    docker volume prune -f
}

# Env
function envs_to_samples() {
    cd env || error_exit "cd"

    # Clean all samples
    find . -type f -iname "sample*" -delete

    # Create new samples
    for f in $(find . -type f -iname ".env*" | cut -d/ -f2); do
        cat "${f}" | cut -d '=' -f1 | xargs -I "%" echo "%=" >"sample${f}"
    done

    cd .. || error_exit "cd"
}

function samples_to_envs() {
    cd env || error_exit "cd"

    # Clean all samples
    find . -type f -iname ".env*" -delete

    # Create new samples
    for f in $(find . -type f -iname "sample2" | cut -d/ -f2); do
        cat "${f}" | cut -d '=' -f1 | xargs -I "%" echo "%=" >"sample${f}"
    done

    cd .. || error_exit "cd"
}

# Django
function django_createsuperuser() {
    cd src || error_exit "cd"
    python3 manage.py createsuperuser
    cd .. || error_exit "cd"
}

function django_clean_migrations() {
    for path in $(find src -type d -iname "migrations"); do
        find "${path}" -type f | grep --invert-match "__init__.py" | xargs ${RM}
    done
    rm src/db.sqlite3
}

function django_loaddata() {
    cd src || error_exit "cd"
    python3 manage.py makemigrations
    python3 manage.py migrate
    python3 manage.py loaddata "./authentication/fixtures/users.json" \
        "./authentication/fixtures/attendants.json" \
        "./customer/fixtures/customers.json" \
        "./product/fixtures/products.json" \
        "./statistic/fixtures/statistics.json"
    cd .. || error_exit "cd"
}

function django_update_product_status() {
    cd src || error_exit "cd"
    python3 manage.py update_product_status
    cd .. || error_exit "cd"
}

function set_cron() {
    cd src || error_exit "cd"
    python3 manage.py crontab add
    cd .. || error_exit "cd"
}

function cron_restart() {
    service cron restart
}

# Others
function create_venv() {
    python3 -m venv venv
    deactivate
    source venv/bin/activate.fish
    pip3 install -r requirements.txt
    deactivate
}

function usage() {
    echo "USAGE:
    '--rm-docker-images-volumes') rm_docker_images_volumes ;;
    '--build-up-docker') build_up_docker ;;
    '--docker-show-ipaddress') docker_show_ipaddress ;;
        # Env
    '--envs-to-samples') envs_to_samples ;;
    '--samples-to-envs') samples_to_envs ;;
        # Django
    '--runserver-dev') django_runserver_dev ;;
    '--runserver-web') django_runserver_web ;;
    '--createsuperuser') django_createsuperuser ;;
    '--clean-migrations') django_clean_migrations ;;
    '--loaddata') django_loaddata ;;
    '--update-product-status') django_update_product_status ;;
    '--set-cron') set_cron ;;
        # Others
    '--venv') create_venv ;;
    '-h' | '--help') usage ;;
    '-c' | '--clean') clean ;;
    '--tags') tags ;;
    '--cloc') custom_cloc ;;
"
}

function clean() {
    #    ${RM} *.zip

    # Folders
    for folder in "venv" "__pycache__"; do
        find . -type d -iname "${folder}" | xargs ${RM}
    done

    # Files
    for file in ".DS_Store" "*.log"; do
        find . -type f -iname "${file}" | xargs ${RM}
    done

    #    django_clean_migrations
}

function tags() {
    ctags -R .
    cscope -Rb
}

function custom_cloc() {
    cloc --not-match-d=migrations --include-lang=Python src/
}

function runserver_local_or_docker() {
    cd src || error_exit"cd"
    python3 manage.py runserver 0.0.0.0:8000
    cd .. || error_exit"cd"
}

function runsever_heroku() {
    cd src || error_exit "cd"
    gunicorn --timeout 1000 --workers=3 --bind=0.0.0.0:"$PORT" --log-level debug config.wsgi:application --reload
    cd .. || error_exit"cd"
}

function set_and_run_cron() {
    chmod +s /usr/bin/crontab

    service cron start

    cd src || error_exit "cd"
    python3 manage.py crontab add
    python3 manage.py crontab show
    cd .. || error_exit "cd"

    service cron restart
}

function web_docker() {
#    set_and_run_cron

    django_loaddata

    runsever_heroku
}

function dev_docker() {
    set_and_run_cron

    django_loaddata

    runserver_local_or_docker
}

function cron_docker() {
    cd src || error_exit "cd"
    python3 manage.py crontab add
    python3 manage.py crontab show
    cd .. || error_exit "cd"

    cron -f
}

# Main arguments loop
[[ "$#" -eq 0 ]] && usage && exit 0
while [ "$#" -gt 0 ]; do
    case "$1" in

    # Docker
    '--rm-docker-images-volumes') rm_docker_images_volumes ;;
    '--build-up-docker') build_up_docker ;;
    '--docker-show-ipaddress') docker_show_ipaddress ;;

        # Env
    '--envs-to-samples') envs_to_samples ;;
    '--samples-to-envs') samples_to_envs ;;

        # Django
    '--createsuperuser') django_createsuperuser ;;
    '--clean-migrations') django_clean_migrations ;;
    '--loaddata') django_loaddata ;;
    '--update-product-status') django_update_product_status ;;
    '--runserver') runserver_local_or_docker ;;
    '--web-docker') web_docker ;;
    '--dev-docker') dev_docker ;;
    '--cron-docker') cron_docker ;;

        # Others
    '--venv') create_venv ;;
    '-h' | '--help') usage ;;
    '-c' | '--clean') clean ;;
    '--tags') tags ;;
    '--cloc') custom_cloc ;;
    esac
    shift
done
