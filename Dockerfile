# Используем базовый образ Ubuntu 22.04
FROM ubuntu:22.04

# Устанавливаем необходимые зависимости
RUN apt update
RUN apt install software-properties-common gnupg -y
RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 1A127079A92F09ED
RUN add-apt-repository 'deb https://apt.kitware.com/ubuntu/ jammy main'
RUN add-apt-repository ppa:ubuntu-toolchain-r/test -y
RUN apt update
RUN apt install build-essential gcc-13 g++-13 cmake git gdb libgtest-dev libboost-all-dev -y
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 140 --slave /usr/bin/g++ g++ /usr/bin/g++-13

# Копируем исходники проекта в контейнер
COPY . /app

# Устанавливаем рабочую директорию
WORKDIR /app

# Сконфигурируем проект (замените на вашу команду конфигурации)
RUN cmake --workflow --preset wsl-ci

# Копируем deb-пакет на хост-машину
CMD ["sh", "-c","cd .. && cp ./build/install/*.deb /host/"]