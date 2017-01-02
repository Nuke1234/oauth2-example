FROM node:alpine
RUN npm install -g forever
RUN npm install -g nodemon

RUN mkdir /app
WORKDIR /app
COPY package.json /app
RUN npm install
COPY . /app
EXPOSE 9000 5858
CMD ["npm", "start"]