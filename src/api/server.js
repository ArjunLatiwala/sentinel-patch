const express = require('express');
const app = express();
const PORT = process.env.PORT || 8080;

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP', service: 'Sentinel-Gateway' });
});

app.listen(PORT, () => {
    console.log(`Sentinel Enterprise Gateway running on port ${PORT}`);
});