// 记录的类型定义 —— 独立成 .ts 供多个组件共用
//
// 以前 ScheduleEvent 只在 page.tsx 里（interface 不 export），
// DayCard、MonthView 这些子组件拿不到类型 —— 只能各写一份或者用 any。
// 抽出来放这里，类型只有一处定义。

export interface ScheduleEvent {
  id: string;
  title: string;
  date: string;
  time: string;
  endTime: string;
  /** 跨日事件的结束日期（含当天，YYYY-MM-DD）；空 = 不跨日 */
  endDate?: string;
  location: string;
  people: string;
  raw: string;
  updatedAt: number;
  /** 'event' 有时间 · 'task' 没时间 · 'project' 项目 */
  type: 'event' | 'task' | 'project';
  completed: boolean;
  /** 0 = 规则没解出日期，待用户确认；1 = 已确认 */
  dateConfirmed?: 0 | 1;
  /** 这条已经同步到服务端了。
   *  没同步过的本地记录不能被删除对账清掉 ——
   *  否则未登录时记的东西，一登录就没了。 */
  synced?: boolean;
}
