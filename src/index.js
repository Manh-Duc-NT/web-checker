

// Import các hàm kiểm tra lỗ hổng từ module utils/functions
const {
  checkForXSS,
  checkForSQLInjection,
  checkForCSRF1,
  checkForCommandInjection,
  checkForFileInclusion,
  checkForIDOR,
  checkForCSRF2,
  checkForUnvalidatedRedirects,
  checkForSSRF,
} = require("./utils/functions");

// Import thư viện axios để thực hiện các yêu cầu HTTP
const axios = require("axios");

// Import thư viện cheerio để phân tích cú pháp HTML và XML
const cheerio = require("cheerio");

// Hàm quét website để phát hiện các lỗ hổng bảo mật
async function scanWebsite(url) {
  try {
    // Gửi yêu cầu GET đến URL được cung cấp
    const response = await axios.get(url);

    // Kiểm tra mã trạng thái của phản hồi
    if (response.status !== 200) {
      // Nếu mã trạng thái không phải là 200, ném một ngoại lệ
      throw new Error(
        `Website at ${url} returned a ${response.status} status code.`
      );
    }

    // Sử dụng cheerio để phân tích cú pháp HTML của phản hồi
    const $ = cheerio.load(response.data);

    // Khởi tạo một mảng để lưu trữ các lỗ hổng được phát hiện
    const vulnerabilities = [];

    // Kiểm tra từng loại lỗ hổng bằng cách gọi các hàm kiểm tra tương ứng
    const xssResult = checkForXSS($, url);
    const sqlInjectionResult = checkForSQLInjection($, url);
    const csrf1Result = checkForCSRF1($, url);
    const commandInjectionResult = checkForCommandInjection($, url);
    const fileInclusionResult = checkForFileInclusion($, url);
    const idorResult = checkForIDOR($, url);
    const csrf2Result = checkForCSRF2($, url);
    const unvalidatedRedirectsResult = checkForUnvalidatedRedirects($, url);
    const ssrfResult = checkForSSRF($, url);

    // Thêm kết quả kiểm tra vào mảng lỗ hổng nếu được phát hiện
    if (xssResult) vulnerabilities.push(xssResult);
    if (sqlInjectionResult) vulnerabilities.push(sqlInjectionResult);
    if (csrf1Result) vulnerabilities.push(csrf1Result);
    if (commandInjectionResult) vulnerabilities.push(commandInjectionResult);
    if (fileInclusionResult) vulnerabilities.push(fileInclusionResult);
    if (idorResult) vulnerabilities.push(idorResult);
    if (csrf2Result) vulnerabilities.push(csrf2Result);
    if (unvalidatedRedirectsResult) vulnerabilities.push(unvalidatedRedirectsResult);
    if (ssrfResult) vulnerabilities.push(ssrfResult);

    // Trả về mảng lỗ hổng nếu có lỗ hổng được phát hiện, ngược lại trả về thông báo rằng website không có lỗ hổng
    return vulnerabilities.length > 0 ? vulnerabilities : `Website at ${url} is not vulnerable.`;
  } catch (error) {
    // Bắt lỗi nếu có bất kỳ lỗi nào xảy ra trong quá trình quét
    console.log(`Error scanning ${url}: ${error}`);
  }
}

// Xuất hàm quét website để có thể sử dụng từ bên ngoài module
module.exports = {
  scanWebsite,
};
