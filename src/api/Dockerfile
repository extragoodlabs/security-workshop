FROM node:18-alpine

ENV NODE_ENV=production

RUN apk add --no-cache tini

WORKDIR /usr/src/app
COPY package*.json ./

RUN yarn install --frozen-lockfile

COPY . .
RUN chown node:node -R .

EXPOSE 3000
USER node
ENTRYPOINT ["/sbin/tini", "--"]
CMD [ "node", "./bin/www" ]
