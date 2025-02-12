

// Hàm kiểm tra lỗ hổng XSS
function checkForXSS($, url) {
  // Lấy tất cả các trường nhập liệu có type là "text"
  const inputFields = $("input[type=text]");
  
  // Nếu tìm thấy ít nhất một trường nhập liệu
  if (inputFields.length > 0) {
    // Lấy tên của các trường nhập liệu và kết hợp chúng thành một chuỗi
    const vulnerableFields = inputFields
      .map((index, field) => $(field).attr("name"))
      .get()
      .join(", ");
    
    // Tạo đối tượng kết quả báo cáo về lỗ hổng XSS
    const result = {
      vulnerability: "XSS",
      url: url,
      vulnerableFields: vulnerableFields,
    };
    
    return result; // Trả về kết quả
  }
  
  return null; // Trả về null nếu không tìm thấy lỗ hổng
}

// Hàm kiểm tra lỗ hổng SQL Injection
function checkForSQLInjection($, url) {
  // Lấy tất cả các biểu mẫu trên trang
  const forms = $("form");
  
  // Nếu tìm thấy ít nhất một biểu mẫu
  if (forms.length > 0) {
    // Lấy ID của các biểu mẫu và kết hợp chúng thành một chuỗi
    const vulnerableForms = forms
      .map((index, form) => $(form).attr("id"))
      .get()
      .join(", ");
    
    // Tạo đối tượng kết quả báo cáo về lỗ hổng SQL Injection
    const result = {
      vulnerability: "SQLInjection",
      url: url,
      vulnerableForms: vulnerableForms,
    };
    
    return result; // Trả về kết quả
  }
  
  return null; // Trả về null nếu không tìm thấy lỗ hổng
}

// Hàm kiểm tra lỗ hổng CSRF1 (Cross-Site Request Forgery)
function checkForCSRF1($, url) {
  // Lấy tất cả các cookie trên trang
  const cookies = $("meta[name=cookies]");
  
  // Nếu tìm thấy ít nhất một cookie
  if (cookies.length > 0) {
    // Tạo đối tượng kết quả báo cáo về lỗ hổng CSRF1
    const result = {
      vulnerability: "CSRF",
      url: url,
      message: "Ensure proper anti-CSRF measures are in place. 'meta[name=cookies]'",
    };
    
    return result; // Trả về kết quả
  }
  
  return null; // Trả về null nếu không tìm thấy lỗ hổng
}

// Hàm kiểm tra lỗ hổng Command Injection
function checkForCommandInjection($, url) {
  // Lấy tất cả các phần tử nhập liệu (input, textarea, select) và lọc ra những phần tử có giá trị chứa ký tự ";"
  const userControlledInput = $("input, textarea, select").filter(
    (index, el) => {
      const value = $(el).val();
      return value && value.match(/;/); // Biểu thức chính quy để phát hiện lỗ hổng Command Injection
    }
  );

  // Nếu tìm thấy ít nhất một phần tử nhập liệu có lỗ hổng
  if (userControlledInput.length > 0) {
    // Tạo đối tượng kết quả báo cáo về lỗ hổng Command Injection
    const result = {
      vulnerability: "CommandInjection",
      url: url,
      message: "Vulnerable to command injection attacks.",
    };
    
    return result; // Trả về kết quả
  }
  
  return null; // Trả về null nếu không tìm thấy lỗ hổng
}

// Hàm kiểm tra lỗ hổng File Inclusion
function checkForFileInclusion($, url) {
  // Lấy tất cả các phần tử nhập liệu (input, textarea, select) và lọc ra những phần tử có giá trị chứa ký tự ".."
  const userControlledInput = $("input, textarea, select").filter(
    (index, el) => {
      const value = $(el).val();
      return value && value.match(/\.\.\//); // Biểu thức chính quy để phát hiện lỗ hổng File Inclusion
    }
  );

  // Nếu tìm thấy ít nhất một phần tử nhập liệu có lỗ hổng
  if (userControlledInput.length > 0) {
    // Tạo đối tượng kết quả báo cáo về lỗ hổng File Inclusion
    const result = {
      vulnerability: "FileInclusion",
      url: url,
      message: "Vulnerable to file inclusion attacks.",
    };
    
    return result; // Trả về kết quả
  }
  
  return null; // Trả về null nếu không tìm thấy lỗ hổng
}

// Hàm kiểm tra lỗ hổng IDOR (Insecure Direct Object References)
function checkForIDOR($, url) {
  // Lấy tất cả các phần tử có class là "sensitive-resource"
  const sensitiveResource = $(".sensitive-resource");
  
  // Nếu tìm thấy ít nhất một phần tử nhạy cảm
  if (sensitiveResource.length > 0) {
    // Tạo đối tượng kết quả báo cáo về lỗ hổng IDOR
    const result = {
      vulnerability: "IDOR",
      url: url,
      message: "Vulnerable to insecure direct object references.",
    };
    
    return result; // Trả về kết quả
  }
  
  return null; // Trả về null nếu không tìm thấy lỗ hổng
}

// Hàm kiểm tra lỗ hổng CSRF2 (Cross-Site Request Forgery)
function checkForCSRF2($, url) {
  // Lấy phần tử meta có name là "csrf-token"
  const csrfToken = $("meta[name=csrf-token]");
  
  // Nếu không tìm thấy phần tử hoặc giá trị của nó trống
  if (!csrfToken || !csrfToken.attr("content")) {
    // Tạo đối tượng kết quả báo cáo về lỗ hổng CSRF2
    const result = {
      vulnerability: "CSRF",
      url: url,
      message: "'meta[name=csrf-token]' is missing or empty. Vulnerable to CSRF attacks.",
    };
    
    return result; // Trả về kết quả
  }
  
  return null; // Trả về null nếu không tìm thấy lỗ hổng
}

// Hàm kiểm tra lỗ hổng Unvalidated Redirects
function checkForUnvalidatedRedirects($, url) {
  // Lấy phần tử a có class là "redirect-link"
  const redirectLink = $("a.redirect-link");
  
  // Nếu tìm thấy ít nhất một phần tử và liên kết không hợp lệ
  if (redirectLink.length > 0 && !isValidRedirect(redirectLink.attr("href"))) {
    // Tạo đối tượng kết quả báo cáo về lỗ hổng Unvalidated Redirects
    const result = {
      vulnerability: "UnvalidatedRedirects",
      url: url,
      message: "Vulnerable to unvalidated redirects and forwards.",
    };
    
    return result; // Trả về kết quả
  }
  
  return null; // Trả về null nếu không tìm thấy lỗ hổng hoặc liên kết hợp lệ
}

// Hàm kiểm tra lỗ hổng SSRF (Server-Side Request Forgery)
function checkForSSRF($, url) {
  // Lấy tất cả các phần tử nhập liệu (input, textarea) và lọc ra những phần tử có giá trị bắt đầu với "http://" hoặc "https://"
  const userControlledURL = $("input, textarea").filter((index, el) => {
    const value = $(el).val();
    return value && value.match(/^https?:\/\/example\.com/); // Biểu thức chính quy để phát hiện lỗ hổng SSRF
  });

  // Nếu tìm thấy ít nhất một phần tử nhập liệu có lỗ hổng
  if (userControlledURL.length > 0) {
    // Tạo đối tượng kết quả báo cáo về lỗ hổng SSRF
    const result = {
      vulnerability: "SSRF",
      url: url,
      message: "Vulnerable to server-side request forgery.",
    };
    
    return result; // Trả về kết quả
  }
  
  return null; // Trả về null nếu không tìm thấy lỗ hổng
}

// Hàm kiểm tra tính hợp lệ của liên kết
function isValidRedirect(href) {
  // Thực hiện kiểm tra tính hợp lệ của liên kết ở đây (có thể kiểm tra domain, path, vv.)
  return true; // Đây là một ví dụ đơn giản, trả về true cho mọi liên kết
}

// Xuất các hàm kiểm tra lỗ hổng để có thể sử dụng từ bên ngoài module
module.exports = {
  checkForXSS,
  checkForSQLInjection,
  checkForCSRF1,
  checkForCommandInjection,
  checkForFileInclusion,
  checkForIDOR,
  checkForCSRF2,
  checkForUnvalidatedRedirects,
  checkForSSRF,
};
