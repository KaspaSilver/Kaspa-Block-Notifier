# Kaspa-Block-Notifier

A Dockerized watcher that sends you a private encrypted **KaChat message** every time your Kaspa node finds a block reward.

Built on the [Kasia protocol](https://github.com/K-Kluster/Kasia) — messages are end-to-end encrypted using ephemeral ECDH + ChaCha20-Poly1305. Only you can read them.

---

## How it works

1. Connects to your local `kaspad` node via gRPC and subscribes to UTXO changes on your mining address
2. When a block reward arrives it encrypts a message using the Kasia protocol
3. Broadcasts a self-spend Kaspa transaction with the encrypted message as the payload
4. KaChat on your phone decrypts and displays the notification

Cost per notification: ~0.002 KAS in transaction fees (pure self-spend, no KAS sent anywhere).

---

# Setup

## Installation
  <details>
  <summary>Building on Linux</summary>

Download docker
```
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your user to the docker group (so you don't need sudo)
sudo usermod -aG docker $USER

# Enable Docker to start on boot
sudo systemctl enable docker
sudo systemctl start docker

# Log out and back in for group changes to take effect
# Then verify it works
docker --version
docker compose version
```

Download git
```
sudo apt install git -y

# Set your identity (shows up in commits)
git config --global user.name "Your Name"
git config --global user.email "your@email.com"

# Verify
git --version
```

Clone This repo
```
git clone https://github.com/KaspaSilver/Kaspa-Block-Notifier.git
```

In terminal cd into the directory you just cloned
```
cd ~/Kaspa-Block-Notifier
```

Edit the .env file with your personal info such as mining address, bot address private key, etc...
```
nano .env
```
Save it with ctrl + o, click enter, then ctrl + x

Build it and run logs to verify it is working
```
docker compose up -d --build
docker logs -f kaspa-block-notifier
```

If working you should see
```
DATE TIME  INFO      Connecting to kaspad at host-gateway:16110

DATE TIME  INFO      Watching address : your mining address

DATE TIME  INFO      Min reward filter: 0.0 KAS

DATE TIME  INFO      Subscribed. Waiting for block rewards...
```

