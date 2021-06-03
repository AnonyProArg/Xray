#!/usr/bin/env bash
cd /etc/VPS-ARG/Xray
clear 
clear

#====================================================================
#███████████████████████████████████████████████████████████████████▀█
#██▀▄─██▄─▀█▄─▄█─▄▄─█▄─▀█▄─▄█▄─█─▄█▄─▄▄─█▄─▄▄▀█─▄▄─██▀▄─██▄─▄▄▀█─▄▄▄▄█
#██─▀─███─█▄▀─██─██─██─█▄▀─███▄─▄███─▄▄▄██─▄─▄█─██─██─▀─███─▄─▄█─██▄─█
#▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▀▄▄▄▀▀▄▄▀▀▄▄▄▀▀▄▄▄▀▀▀▄▄▀▄▄▀▄▄▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀
#===================================================================

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

cd "$(
  cd "$(dirname "$0")" || exit
  pwd
)" || exit

# Configuración de color de fuente
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
ERROR="${Red}[ERROR]${Font}"

# variable
shell_version="1.2.8"
github_branch="main"
xray_conf_dir="/usr/local/etc/xray"
website_dir="/www/xray_web/"
xray_access_log="/var/log/xray/access.log"
xray_error_log="/var/log/xray/error.log"
cert_dir="/usr/local/etc/xray"
domain_tmp_dir="/usr/local/etc/xray"
cert_group="nobody"
random_num=$((RANDOM % 12 + 4))

VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')
WS_PATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})/"

function shell_mode_check() {
  if [ -f ${xray_conf_dir}/config.json ]; then
    if [ "$(grep -c "wsSettings" ${xray_conf_dir}/config.json)" -ge 1 ]; then
      shell_mode="ws"
    else
      shell_mode="tcp"
    fi
  else
    shell_mode="None"
  fi
}
function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "El usuario actual es el usuario root, inicie el proceso de instalación"
  else
    print_error "El usuario actual no es el usuario root, cambie al usuario root y vuelva a ejecutar el script"
    exit 1
  fi
}

judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 REAIZADO"
    sleep 1
  else
    print_error "$1 falla"
    exit 1
  fi
}

function system_check() {
  source '/etc/os-release'

  if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
    print_ok "El sistema actual es Centos ${VERSION_ID} ${VERSION}"
    INS="yum install -y"
    wget -N -P /etc/yum.repos.d/ https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/basic/nginx.repo
  elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
    print_ok "El sistema actual es Debian ${VERSION_ID} ${VERSION}"
    INS="apt install -y"
    # Elimina posibles problemas restantes
    rm -f /etc/apt/sources.list.d/nginx.list
    $INS lsb-release gnupg2

    echo "deb http://nginx.org/packages/debian $(lsb_release -cs) nginx" >/etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo apt-key add -

    apt update
  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
    print_ok "El sistema actual es Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
    INS="apt install -y"
    # Elimina posibles problemas restantes
    rm -f /etc/apt/sources.list.d/nginx.list
    $INS lsb-release gnupg2

    echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" >/etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | sudo apt-key add -
    apt update
  else
    print_error "El sistema actual es ${ID} ${VERSION_ID} No en la lista de sistemas compatibles"
    exit 1
  fi

  if [[ $(grep "nogroup" /etc/group) ]]; then
    cert_group="nogroup"
  fi

  $INS dbus

  # Apague todo tipo de firewalls
  systemctl stop firewalld
  systemctl disable firewalld
  systemctl stop nftables
  systemctl disable nftables
  systemctl stop ufw
  systemctl disable ufw
}

function nginx_install() {
  if ! command -v nginx >/dev/null 2>&1; then
    ${INS} nginx
    judge "Nginx instalación"
  else
    print_ok "Nginx existió"
  fi
}
function dependency_install() {
  ${INS} wget lsof tar
  judge "instalación wget lsof tar"

  if [[ "${ID}" == "centos" ]]; then
    ${INS} crontabs
  else
    ${INS} cron
  fi
  judge "instalación crontab"

  if [[ "${ID}" == "centos" ]]; then
    touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
    systemctl start crond && systemctl enable crond
  else
    touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
    systemctl start cron && systemctl enable cron

  fi
  judge "crontab Configuración de arranque automático "

  ${INS} unzip
  judge "instalación unzip"

  ${INS} curl
  judge "instalación curl"

  # upgrade systemd
  ${INS} systemd
  judge "Instalación / actualización systemd"

  # Nginx Publicar No es necesario compilar Ya no es necesario
  #  if [[ "${ID}" == "centos" ]]; then
  #    yum -y groupinstall "Development tools"
  #  else
  #    ${INS} build-essential
  #  fi
  #  judge "Instalación del kit de herramientas de compilación"

  if [[ "${ID}" == "centos" ]]; then
    ${INS} pcre pcre-devel zlib-devel epel-release openssl openssl-devel
  else
    ${INS} libpcre3 libpcre3-dev zlib1g-dev openssl libssl-dev
  fi

  ${INS} jq

  if ! command -v jq; then
    wget -P /usr/bin https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/binary/jq && chmod +x /usr/bin/jq
    judge "instalación jq"
  fi
}

function basic_optimization() {
  # Número máximo de archivos abiertos
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf

  # cerrar Selinux
  if [[ "${ID}" == "centos" ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    setenforce 0
  fi
}
function domain_check() {
  read -rp "Ingrese la información de su nombre de dominio(eg: www.wulabing.com):" domain
  domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
  print_ok "Obteniendo información de la dirección IP, espere pacientemente"
  local_ip=$(curl -4 ip.sb)
  echo -e "La dirección IP del nombre de dominio resuelto por DNS：${domain_ip}"
  echo -e "Dirección IP de la red pública local： ${local_ip}"
  sleep 2
  if [[ ${domain_ip} == "${local_ip}" ]]; then
    print_ok "La dirección IP del nombre de dominio resuelto por DNS coincide con la dirección IP de la máquina"
    sleep 2
  else
    print_error "Asegúrese de agregar el registro A correcto al nombre de dominio; de lo contrario, no funcionará correctamente xray"
    print_error "La dirección IP del nombre de dominio resuelto por DNS no coincide con la dirección IP de la máquina, si continuar con la instalación？（y/n）" && read -r install
    case $install in
    [yY][eE][sS] | [yY])
      print_ok "Continuar con la instalación"
      sleep 2
      ;;
    *)
      print_error "Instalación terminada"
      exit 2
      ;;
    esac
  fi
}

function port_exist_check() {
  if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
    print_ok "$1 El puerto no está ocupado"
    sleep 1
  else
    print_error "detectado $1 El puerto está ocupado, lo siguiente es $1 Información de ocupación del puerto"
    lsof -i:"$1"
    print_error "5s Intentará matar automáticamente el proceso ocupado"
    sleep 5
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    print_ok "KILL REALIZADO
    
    
    
    
    
    
    
    "
    sleep 1
  fi
}
function update_sh() {
  ol_version=$(curl -L -s https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/install.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [[ "$shell_version" != "$(echo -e "$shell_version\n$ol_version" | sort -rV | head -1)" ]]; then
    print_ok "Hay una nueva versión, ya sea para actualizar [Y/N]?"
    read -r update_confirm
    case $update_confirm in
    [yY][eE][sS] | [yY])
      wget -N --no-check-certificate https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/install.sh
      print_ok "actualización completada"
      print_ok "Puedes pasar bash $0 Ejecute este procedimiento"
      exit 0
      ;;
    *) ;;

    esac
  else
    print_ok "La versión actual es la última versión."
    print_ok "Puedes pasar bash $0 Ejecute este procedimiento"
  fi
}

function xray_tmp_config_file_check_and_use() {
  if [[ -s ${xray_conf_dir}/config_tmp.json ]]; then
    mv -f ${xray_conf_dir}/config_tmp.json ${xray_conf_dir}/config.json
  else
    print_error "xray Modificación anormal del archivo de configuración"
  fi
}

function modify_UUID() {
  [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray TCP UUID modificar"
}

function modify_UUID_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray ws UUID modificar"
}

function modify_fallback_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","fallbacks",2,"path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray fallback_ws modificar"
}

function modify_ws() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",1,"streamSettings","wsSettings","path"];"'${WS_PATH}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray ws modificar"
}
function modify_tls_version() {
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"streamSettings","xtlsSettings","minVersion"];"'$1'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray TLS_version modificar"
}

function configure_nginx() {
  nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  cd /etc/nginx/conf.d/ && rm -f ${domain}.conf && wget -O ${domain}.conf https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/web.conf
  sed -i "/server_name/c \\\tserver_name ${domain};" ${nginx_conf}
  judge "Nginx config modify"

  systemctl restart nginx
}

function tls_type() {
  echo "Seleccione admitido TLS versión（defecto：TLS1.3 only）:"
  echo "1: TLS1.1, TLS1.2 and TLS1.3（Modo de compatibilidad）"
  echo "2: TLS1.2 and TLS1.3 (Modo de compatibilidad)"
  echo "3: TLS1.3 only"
  read -rp "por favor escribe：" tls_version
  [[ -z ${tls_version} ]] && tls_version=3
  if [[ $tls_version == 3 ]]; then
    modify_tls_version "1.3"
  elif [[ $tls_version == 2 ]]; then
    modify_tls_version "1.2"
  else
    modify_tls_version "1.1"
  fi
}

function modify_port() {
  read -rp "Introduzca el número de puerto (predeterminado：443)：" PORT
  [ -z "$PORT" ] && PORT="443"
  if [[ $PORT -le 0 ]] || [[ $PORT -gt 65535 ]]; then
    print_error "por favor escribe 0-65535 Valor entre"
    exit 1
  fi
  port_exist_check $PORT
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"port"];'${PORT}')' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray Modificación de puerto"
}

function configure_xray() {
  cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/xray_xtls-rprx-direct.json
  modify_UUID
  modify_port
  tls_type
}

function configure_xray_ws() {
  cd /usr/local/etc/xray && rm -f config.json && wget -O config.json https://raw.githubusercontent.com/wulabing/Xray_onekey/${github_branch}/config/xray_tls_ws_mix-rprx-direct.json
  modify_UUID
  modify_UUID_ws
  modify_port
  modify_fallback_ws
  modify_ws
  tls_type
}

function xray_install() {
  print_ok "instalación Xray"
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
  judge "Instalación de Xray"

  # Utilizado para generar Xray Importar enlace
  echo $domain >$domain_tmp_dir/domain
  judge "Registro de dominio"
}

function ssl_install() {
  #  Utilice Nginx para cooperar con la emisión, no es necesario instalar dependencias relacionadas
  #  if [[ "${ID}" == "centos" ]]; then
  #    ${INS} socat nc
  #  else
  #    ${INS} socat netcat
  #  fi
  #  judge "Instalar la dependencia del script de generación de certificados SSL"

  curl https://get.acme.sh | sh
  judge "Instale el script de generación de certificados SSL"
}

function acme() {

  sed -i "6s/^/#/" "$nginx_conf"

  # Inicie Nginx Xray y use Nginx con acme para la emisión de certificados
  systemctl restart nginx
  systemctl restart xray

  if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --nginx -k ec-256 --force; then
    print_ok "Certificado SSL generado con éxito"
    sleep 2
    if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --reloadcmd "systemctl restart xray" --ecc --force; then
      print_ok "La configuración del certificado SSL es exitosa"
      sleep 2
    fi
  else
    print_error "Error al generar el certificado SSL"
    rm -rf "$HOME/.acme.sh/${domain}_ecc"
    exit 1
  fi

  sed -i "6s/#//" "$nginx_conf"
}

function ssl_judge_and_install() {

  mkdir -p /ssl
  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    echo "El archivo de certificado en el directorio / ssl ya existe"
    print_ok "eliminar [Y/N]?"
    read -r ssl_delete
    case $ssl_delete in
    [yY][eE][sS] | [yY])
      rm -rf /ssl/*
      print_ok "eliminado"
      ;;
    *) ;;

    esac
  fi

  if [[ -f "/ssl/xray.key" || -f "/ssl/xray.crt" ]]; then
    echo "El archivo de certificado ya existe"
  elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
    echo "El archivo de certificado ya existe"
    "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /ssl/xray.crt --keypath /ssl/xray.key --ecc
    judge "Solicitud de certificado"
  else
    mkdir /ssl
    cp -a $cert_dir/self_signed_cert.pem /ssl/xray.crt
    cp -a $cert_dir/self_signed_key.pem /ssl/xray.key
    ssl_install
    acme
  fi

  # Xray se ejecuta como el usuario de nadie de forma predeterminada y los permisos del certificado se adaptan
  chown -R nobody.$cert_group /ssl/*
}

function generate_certificate() {
  signedcert=$(xray tls cert -domain="$local_ip" -name="$local_ip" -org="$local_ip" -expire=87600h)
  echo $signedcert | jq '.certificate[]' | sed 's/\"//g' | tee $cert_dir/self_signed_cert.pem
  echo $signedcert | jq '.key[]' | sed 's/\"//g' > $cert_dir/self_signed_key.pem
  openssl x509 -in $cert_dir/self_signed_cert.pem -noout || print_error "No se pudo generar el certificado autofirmado"
  print_ok "Certificado autofirmado generado con éxito"
  chown nobody.$cert_group $cert_dir/self_signed_cert.pem
  chown nobody.$cert_group $cert_dir/self_signed_key.pem
}

function configure_web() {
  rm -rf /www/xray_web
  mkdir -p /www/xray_web
  wget -O web.tar.gz https://raw.githubusercontent.com/wulabing/Xray_onekey/main/basic/web.tar.gz
  tar xzf web.tar.gz -C /www/xray_web
  judge "Camuflaje del sitio"
  rm -f web.tar.gz
}

function xray_uninstall() {
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
  systemctl stop nginx
  rm -rf $website_dir
  print_ok "Desinstalación completa"
  exit 0
}

function restart_all() {
  systemctl restart nginx
  judge "Inicio de Nginx"
  systemctl restart xray
  judge "Inicio de la xray"
}

function vless_xtls-rprx-direct_link() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  print_ok "Enlace URL（VLESS + TCP +  TLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=tls&flow=$FLOW#TLS_wulabing-$DOMAIN"

  print_ok "Enlace URL（VLESS + TCP +  XTLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=xtls&flow=$FLOW#XTLS_wulabing-$DOMAIN"
  print_ok "-------------------------------------------------"
  print_ok "Código QR URL（VLESS + TCP + TLS）（Visite en su navegador）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=tls%26flow=$FLOW%23TLS_wulabing-$DOMAIN"

  print_ok "Código QR URL（VLESS + TCP + XTLS）（Visite en su navegador）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=xtls%26flow=$FLOW%23XTLS_wulabing-$DOMAIN"
}

function vless_xtls-rprx-direct_information() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  echo -e "${Red} Información de configuración de rayos X ${Font}"
  echo -e "${Red} habla a（address）:${Font}  $DOMAIN"
  echo -e "${Red} Puerto（port）：${Font}  $PORT"
  echo -e "${Red} ID de usuario（UUID）：${Font} $UUID"
  echo -e "${Red} Control de flujo（flow）：${Font} $FLOW"
  echo -e "${Red} Cifrado（security）：${Font} none "
  echo -e "${Red} Protocolo de transferencia（network）：${Font} tcp "
  echo -e "${Red} Tipo de camuflaje（type）：${Font} none "
  echo -e "${Red} Seguridad de transmisión subyacente：${Font} xtls o tls"
}

function ws_information() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  WS_PATH=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.fallbacks[2].path | tr -d '"')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  echo -e "${Red} Información de configuración de Xray ${Font}"
  echo -e "${Red} habla a（address）:${Font}  $DOMAIN"
  echo -e "${Red} Puerto（port）：${Font}  $PORT"
  echo -e "${Red} ID de usuario（UUID）：${Font} $UUID"
  echo -e "${Red} Cifrado（security）：${Font} none "
  echo -e "${Red} Protocolo de transferencia（network）：${Font} ws "
  echo -e "${Red} Tipo de camuflaje（type）：${Font} none "
  echo -e "${Red} camino（path）：${Font} $WS_PATH "
  echo -e "${Red} Seguridad de transmisión subyacente：${Font} tls "
}

function ws_link() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  PORT=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].port)
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  WS_PATH=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.fallbacks[2].path | tr -d '"')
  WS_PATH_WITHOUT_SLASH=$(echo $WS_PATH | tr -d '/')
  DOMAIN=$(cat ${domain_tmp_dir}/domain)

  print_ok "Enlace URL（VLESS + TCP + TLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=tls#TLS_wulabing-$DOMAIN"

  print_ok "Enlace URL（VLESS + TCP + XTLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?security=xtls&flow=$FLOW#XTLS_wulabing-$DOMAIN"

  print_ok "Enlace URL（VLESS + WebSocket + TLS）"
  print_ok "vless://$UUID@$DOMAIN:$PORT?type=ws&security=tls&path=%2f${WS_PATH_WITHOUT_SLASH}%2f#WS_TLS_wulabing-$DOMAIN"
  print_ok "-------------------------------------------------"
  print_ok "Código QR URL（VLESS + TCP + TLS）（Visite en su navegador）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=tls%23TLS_wulabing-$DOMAIN"

  print_ok "Código QR URL（VLESS + TCP + XTLS）（Visite en su navegador）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?security=xtls%26flow=$FLOW%23XTLS_wulabing-$DOMAIN"

  print_ok "Código QR URL（VLESS + WebSocket + TLS）（Visite en su navegador）"
  print_ok "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless://$UUID@$DOMAIN:$PORT?type=ws%26security=tls%26path=%2f${WS_PATH_WITHOUT_SLASH}%2f%23WS_TLS_wulabing-$DOMAIN"
}

function basic_information() {
  print_ok "VLESS+TCP+XTLS+Nginx Instalación exitosa"
  vless_xtls-rprx-direct_information
  vless_xtls-rprx-direct_link
}

function basic_ws_information() {
  print_ok "VLESS+TCP+TLS+Nginx with WebSocket La instalación en modo mixto se realizó correctamente"
  ws_information
  print_ok "————————————————————————"
  vless_xtls-rprx-direct_information
  ws_link
}

function show_access_log() {
  [ -f ${xray_access_log} ] && tail -f ${xray_access_log} || echo -e "${RedBG}log el archivo no existe${Font}"
}

function show_error_log() {
  [ -f ${xray_error_log} ] && tail -f ${xray_error_log} || echo -e "${RedBG}log el archivo no existe${Font}"
}

function bbr_boost_sh() {
  [ -f "tcp.sh" ] && rm -rf ./tcp.sh
  wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
}

function mtproxy_sh() {
  wget -N --no-check-certificate "https://github.com/wulabing/mtp/raw/master/mtproxy.sh" && chmod +x mtproxy.sh && bash mtproxy.sh
}

function install_xray() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  configure_xray
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  restart_all
  basic_information
}
function install_xray_ws() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  configure_xray_ws
  nginx_install
  configure_nginx
  configure_web
  generate_certificate
  ssl_judge_and_install
  restart_all
  basic_ws_information
}
menu() {
  update_sh
  shell_mode_check
  echo -e "\t 𝕊𝕔𝕣𝕚𝕡𝕥 𝕕𝕖 𝕘𝕖𝕤𝕥𝕚𝕠́𝕟 𝕕𝕖 𝕏𝕣𝕒𝕪 ${Red}[${shell_version}]${Font}"
  echo -e "\t--𝘾𝙧𝙚𝙖𝙙𝙤 𝙥𝙤𝙧: 𝘼𝙣𝙤𝙣𝙮𝙋𝙧𝙤𝘼𝙧𝙜--"
  echo -e         "\tP̷R̷E̷M̷I̷U̷N̷\n"

  echo -e "Versión instalada actualmente：${shell_mode}"
  echo -e "—————————————— Guía de instalación ——————————————"""
  echo -e "${Green}0.${Font}  Actualizar script"
  echo -e "${Green}1.${Font}  instalación Xray (VLESS + TCP + XTLS / TLS + Nginx)"
  echo -e "${Green}2.${Font}  instalación Xray (VLESS + TCP + XTLS / TLS + Nginx y VLESS + TCP + TLS + Nginx + WebSocket Modelo de coexistencia (RECOMENDADO)"
  echo -e "—————————————— Cambios de configuración ——————————————"
  echo -e "${Green}11.${Font} Cambiar UUID"
  echo -e "${Green}12.${Font} Cambiar la versión mínima de adaptación de TLS"
  echo -e "${Green}13.${Font} Cambiar el puerto de conexión"
  echo -e "${Green}14.${Font} Cambiar WebSocket PATH"
  echo -e "—————————————— Ver información ——————————————"
  echo -e "${Green}21.${Font} Ver registro de acceso en tiempo real"
  echo -e "${Green}22.${Font} Ver registro de errores en tiempo real"
  echo -e "${Green}23.${Font} Ver enlace de configuración de Xray"
  #    echo -e "${Green}23.${Font}  Ver información de configuración de V2Ray"
  echo -e "—————————————— Otras opciones ——————————————"
  echo -e "${Green}31.${Font} Instale el script de instalación 4 en 1 BBR, Rui Su"
  echo -e "${Yellow}32.${Font} instalar MTproxy(No recomendado, ciérrelo o desinstálelo)"
  echo -e "${Green}33.${Font} Desinstalar Xray"
  echo -e "${Green}34.${Font} Actualizar Xray-core"
  echo -e "${Green}35.${Font} Instalar Xray-core Beta (Pre)"
  echo -e "${Green}40.${Font} abandonar"
  read -rp "Por favor ingrese los números：" menu_num
  case $menu_num in
  0)
    update_sh
    ;;
  1)
    install_xray
    ;;
  2)
    install_xray_ws
    ;;
  11)
    read -rp "Ingrese UUID:" UUID
    if [[ ${shell_mode} == "tcp" ]]; then
      modify_UUID
    elif [[ ${shell_mode} == "ws" ]]; then
      modify_UUID
      modify_UUID_ws
    fi
    restart_all
    ;;
  12)
    tls_type
    restart_all
    ;;
  13)
    modify_port
    restart_all
    ;;
  14)
    if [[ ${shell_mode} == "ws" ]]; then
      read -rp "Ingrese la ruta (ejemplo: / wulabing / requiere / en ambos lados):" WS_PATH
      modify_fallback_ws
      modify_ws
      restart_all
    else
      print_error "El modo actual no es el modo Websocket"
    fi
    ;;
  21)
    tail -f $xray_access_log
    ;;
  22)
    tail -f $xray_error_log
    ;;
  23)
    if [[ -f $xray_conf_dir/config.json ]]; then
      if [[ ${shell_mode} == "tcp" ]]; then
        basic_information
      elif [[ ${shell_mode} == "ws" ]]; then
        basic_ws_information
      fi
    else
      print_error "El archivo de configuración de xray no existe"
    fi
    ;;
  31)
    bbr_boost_sh
    ;;
  32)
    mtproxy_sh
    ;;
  33)
    xray_uninstall
    ;;
  34)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
    restart_all
    ;;
  35)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install --beta
    restart_all
    ;;
  40)
    exit 0
    ;;
  *)
    print_error "Ingrese el número correcto"
    ;;
  esac
}
menu "$@"
