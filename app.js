require('dotenv').config();
const http = require('http');
const { Server }= require('socket.io');
const express = require('express');
const mongoose = require('mongoose');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const fileUpload = require('express-fileupload');
const rateLimiter = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const cors = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const path = require('path');
const app = express();
const server = http.createServer(app);
// const io = socketIo(server);

const authRouter = require('./routes/authRoutes');
const userRouter = require('./routes/userRoutes');

const notFoundMiddleware = require('./middleware/not-found');
const errorHandlerMiddleware = require('./middleware/error-handler');

app.set('trust proxy', 1);
app.use(
  rateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 60,
  })
);
// const httpServer = createServer(app);
const io = new Server(server, {
  cors: { origin: "http://localhost:5173" },
});
app.use(helmet());
app.use(cors());
app.use(xss());
app.use(mongoSanitize());
app.use(express.json());
app.use(cookieParser(process.env.JWT_SECRET));
app.use(express.static(path.join(__dirname, 'public')));
app.use(fileUpload());

app.use('/api/v1/auth', authRouter);
app.use('/api/v1/users', userRouter);

io.on('connection', (socket) => {
  console.log('App connected');
  socket.on('disconnect', () => {
    console.log('App is disconnected');
  });
});

const getCryptoPrices = async () => {
  try {
    const fetch = await import('node-fetch').then((module) => module.default);
    const options = {
      headers: {
        'Content-Type': 'application/json',
        'x-access-token': process.env.COINRANKING_API_TOKEN,
      },
    };

    const response = await fetch('https://api.coinranking.com/v2/coins', options);
    if (!response.ok) {        
      if (response.status === 429) {
        throw new Error('API Rate Limit Exceeded');
      } else {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
    }

    const data = await response.json();
    if (!data || !data.data || !data.data.coins) {
      throw new Error('Unexpected API response structure');
    }

    const { coins } = data.data;
    const prices = {
      bitcoin: { usd: coins.find((coin) => coin.symbol === 'BTC')?.price },
      ethereum: { usd: coins.find((coin) => coin.symbol === 'ETH')?.price },
      dogecoin: { usd: coins.find((coin) => coin.symbol === 'DOGE')?.price },
    };

    return prices;
  } catch (error) {
    console.error('Error fetching prices:', error.message);

    if (error.message === 'API Rate Limit Exceeded') {
      setTimeout(() => {
        getCryptoPrices();
      }, 60*60*60*2);
    }

    return {};
  }
};

const updatePrices = async () => {
  const prices = await getCryptoPrices();
  console.log('Crypto prices updated:', prices);  
  io.emit('update_prices', prices);
};

setInterval(updatePrices, 60*60*60*2);

const connectToDB = async () => {
  try {
    await mongoose.connect(process.env.DB_STRINGS, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB database...');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error);
  }
};

connectToDB();

app.use(notFoundMiddleware);
app.use(errorHandlerMiddleware);

const host = '0.0.0.0';
const port = process.env.PORT || 5000;
server.listen(port, host, () => {
  console.log(`Server started and listening on http://${host}:${port}`);
});
