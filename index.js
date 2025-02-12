

const express = require('express');
const app = express();
const port = 3000;

// Đặt cấu hình cho EJS template engine
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// Import hàm scanWebsite từ module ./src/index
const { scanWebsite } = require('./src/index');

// Route cho trang chủ
app.get('/', (req, res) => {
  res.render('index');
});

// Route cho trang quét
app.get('/scan', async (req, res) => {
  const url = req.query.url; // Lấy URL từ query parameters
  const vulnerabilities = await scanWebsite(url); // Gọi hàm scanWebsite để quét website
  if (vulnerabilities?.length > 0) {
    // Nếu có lỗ hổng được phát hiện, hiển thị trang vulnerabilities
    res.render('vulnerabilities', { vulnerabilities, url });
  } else {
    // Nếu không có lỗ hổng được phát hiện, hiển thị trang scanResult với thông báo tương ứng
    res.render('scanResult', { message: `Website at ${url} is not vulnerable.` });
  }
});

// Lắng nghe trên cổng được chỉ định
app.listen(port, () => {
  console.log(`Vào link này để dùng web của Mạnh Đức http://localhost:${port}`);
});
