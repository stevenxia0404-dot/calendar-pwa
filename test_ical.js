// 测试 iCal 端点
const TOKEN = 'test';
console.log('访问 https://schedule-api.boluomate.com/events/ical?token=xxx 应该返回 iCalendar 格式');
console.log('如果返回 HTML 或 5xx，说明 Worker 路由/DNS 有问题');
console.log('如果返回 iCal 文本，说明正常');
