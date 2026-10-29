FROM mcr.microsoft.com/playwright:v1.56.1-noble
WORKDIR /worker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark iproute2 iptables dnsutils && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm install --omit=dev
COPY index.js ./
ENV NODE_ENV=production
EXPOSE 4000
CMD ["node", "index.js"]
