const express = require('express');
const app = express();
app.use(express.static(__dirname));
app.listen(8481, () => console.log('Running on https://soulsgames.com:8481'));
