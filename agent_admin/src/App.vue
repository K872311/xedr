<template>
  <div class="app">
    <aside
      class="rail"
      @mouseenter="onNavEnter"
      @mouseleave="onNavLeave"
    >
      <div class="logo" title="EDR 终端安全管理后台">
        <span class="logo-mark">E</span>
        <strong class="logo-name">EDR</strong>
      </div>
      <nav class="rail-nav">
        <button
          v-for="item in railItems"
          :key="item.id"
          type="button"
          class="rail-item"
          :class="{ on: section === item.id }"
          :title="item.label"
          @click="setSection(item.id); menuHover = true"
        >
          <span class="ico" v-html="item.ico" />
          <em>{{ item.short || item.label }}</em>
          <i v-if="item.id === 'detect' && openEventCount" class="dot-n">{{ openEventCount > 99 ? '99+' : openEventCount }}</i>
        </button>
      </nav>
      <div class="rail-bottom">
        <button type="button" class="rail-user" :title="`${user?.display_name || user?.username || ''}（${user?.role_label || ''}）`" @click.stop="userMenuOpen = !userMenuOpen">
          <span class="ru-avatar">{{ userInitial }}</span>
          <em>{{ user?.username }}</em>
        </button>
        <div v-if="userMenuOpen" class="user-pop" @click.stop>
          <div class="up-head">
            <span class="ru-avatar lg">{{ userInitial }}</span>
            <div>
              <strong>{{ user?.display_name || user?.username }}</strong>
              <small>{{ user?.username }} · {{ user?.role_label }}</small>
            </div>
          </div>
          <p v-if="user?.last_login_ip" class="up-meta">本次登录 IP：{{ user.last_login_ip }}</p>
          <button type="button" class="up-item" @click="openPwDialog">修改密码</button>
          <button v-if="isAdmin" type="button" class="up-item" @click="userMenuOpen = false; goMenu('accounts')">账号管理</button>
          <button type="button" class="up-item danger" @click="emit('logout')">退出登录</button>
        </div>
      </div>
    </aside>

    <aside
      class="menu"
      :class="{ open: menuVisible }"
      @mouseenter="onNavEnter"
      @mouseleave="onNavLeave"
    >
      <div class="menu-top">
        <h2>{{ sectionTitle }}</h2>
        <button
          type="button"
          class="menu-pin"
          :class="{ on: menuPinned }"
          :title="menuPinned ? '取消固定' : '固定二级菜单'"
          @click="menuPinned = !menuPinned"
        >{{ menuPinned ? '已固定' : '固定' }}</button>
      </div>
      <template v-for="group in menuGroups" :key="group.title || 'g'">
        <p v-if="group.title" class="menu-group">{{ group.title }}</p>
        <button
          v-for="m in group.items"
          :key="m.id"
          type="button"
          class="menu-item"
          :class="{ on: page === m.id || (m.id === 'events' && (page === 'threat-view' || page === 'events')) || (m.id === 'malware' && page === 'malware') || (m.id === 'whitelist' && page === 'rules' && rulesSection === 'whitelist') }"
          @click="goMenu(m.id)"
        >{{ m.label }}</button>
      </template>
      <p v-if="section === 'asset'" class="menu-hint">
        在终端列表点主机，即可查看进程 / 服务 / 网络等模块数据与可疑行为。
      </p>
      <p v-if="section === 'overview'" class="menu-hint">
        态势 / 调查 / 终端三类快捷入口；点选后会跳到对应分区继续深入。
      </p>
      <p v-if="section === 'detect'" class="menu-hint">
        威胁事件可处置；时间线 / 狩猎 / IOC 在本栏下方菜单。处置结果在详情「处置结果」页签查看。
      </p>
      <p v-if="section === 'deploy'" class="menu-hint">
        「处置审计」可查看谁点了结束进程 / 隔离等操作及结果。
      </p>
      <p v-if="section === 'rules'" class="menu-hint">
        Agent 规则：单条快照特征（可限文件类型）。行为序列：时间窗口内 A→B→C 链式命中。
      </p>
      <p v-if="section === 'ai'" class="menu-hint">
        选择在线终端后自动汇总快照、威胁事件与日志，结合 Skill 调用本地大模型研判。
      </p>
      <p class="menu-hint soft">默认隐藏二级菜单：鼠标移到左侧图标栏可展开；需要常显时点「固定」。</p>
    </aside>

    <div class="workspace" :class="{ 'menu-pinned': menuPinned }">
      <div v-if="error || okMsg || respToast" class="toast-stack">
        <div v-if="error" class="toast err toast-with-x" role="alert">
          <span class="toast-main" @click="clearErrorToast">{{ error }}</span>
          <button type="button" class="toast-x" title="关闭" @click="clearErrorToast">×</button>
        </div>
        <p v-if="okMsg" class="toast ok">{{ okMsg }}</p>
        <div v-if="respToast" class="toast float" :class="respToast.cls" @click="dismissRespToast">
          <div class="toast-main">
            <b>{{ respToast.title }}</b>
            <span>{{ respToast.detail }}</span>
          </div>
          <button type="button" class="toast-x" @click.stop="dismissRespToast">×</button>
        </div>
      </div>

      <!-- ========== 数据概览 ========== -->
      <section v-if="page === 'overview'" class="page overview">
        <header class="page-hd">
          <div>
            <h1>数据概览</h1>
            <p class="desc">威胁优先 · 终端态势 · 一键下钻</p>
          </div>
          <div class="hd-right">
            <span class="live-hint" :class="{ on: liveOk }">
              <i class="live-dot" />
              {{ liveOk ? `已连接 · ${liveAgo}` : '连接中…' }}
            </span>
            <button type="button" class="btn ghost-btn" :disabled="loading" @click="refresh">立即同步</button>
          </div>
        </header>

        <div class="ov-fleet-strip" :class="{ collapsed: ovFleetCollapsed }">
          <div class="ov-fleet-main">
            <section class="ov-fleet-block">
              <header class="ov-fleet-hd">
                <span class="ov-fleet-ico" aria-hidden="true">🖥</span>
                <span>已接入终端</span>
                <i class="ov-info" title="Forensic Agent 注册主机；VA 为无 Agent 探针占位">i</i>
              </header>
              <div class="ov-fleet-metric">
                <strong>{{ ovAgentTotal }}</strong>
                <span class="ov-pill agent">Agent {{ ovAgentTotal }}</span>
                <span class="ov-pill va">VA {{ overviewStats.agents?.va ?? 0 }}</span>
              </div>
              <div class="ov-fleet-sub">
                <div class="ov-fleet-cell click" @click="goPage('hosts')">
                  <em>在线终端</em><b class="c-online">{{ onlineCount }}</b>
                </div>
                <div class="ov-fleet-cell">
                  <em>24小时采集日志</em>
                  <div class="ov-spark-row">
                    <b>{{ overviewStats.timeline_24h?.display ?? '—' }}</b>
                    <svg v-if="overviewSparkTl" class="ov-spark" viewBox="0 0 120 32" preserveAspectRatio="none">
                      <polyline :points="overviewSparkTl" fill="none" stroke="#12b76a" stroke-width="1.5" />
                    </svg>
                  </div>
                </div>
              </div>
            </section>
            <span class="ov-fleet-div" />
            <section class="ov-fleet-block">
              <header class="ov-fleet-hd">
                <span class="ov-fleet-ico" aria-hidden="true">🏢</span>
                <span>职场 / 出口</span>
              </header>
              <div class="ov-fleet-sub three">
                <div class="ov-fleet-cell click" @click="goPage('groups')">
                  <em>已接入分组</em><b>{{ overviewStats.groups ?? 0 }}</b>
                </div>
                <div class="ov-fleet-cell click" @click="openOverviewNetworkView('external')">
                  <em>活跃外联 IP(24h)</em><b>{{ overviewStats.network_exits ?? 0 }}</b>
                </div>
                <div class="ov-fleet-cell click" @click="openOverviewNetworkView('dns')">
                  <em>24小时 DNS 请求</em>
                  <div class="ov-spark-row">
                    <b>{{ overviewStats.dns_24h?.display ?? '—' }}</b>
                    <svg v-if="overviewSparkDns" class="ov-spark" viewBox="0 0 120 32" preserveAspectRatio="none">
                      <polyline :points="overviewSparkDns" fill="none" stroke="#12b76a" stroke-width="1.5" />
                    </svg>
                  </div>
                </div>
              </div>
            </section>
          </div>
          <button type="button" class="ov-fleet-toggle" :aria-expanded="!ovFleetCollapsed" @click="ovFleetCollapsed = !ovFleetCollapsed">
            {{ ovFleetCollapsed ? '展开' : '收起' }}
          </button>
        </div>

        <div class="ov-threat-rail">
          <article class="ov-rail-card click" @click="goPage('events')">
            <div class="ov-rail-ico warn">!</div>
            <div class="ov-rail-body">
              <span>告警主机</span>
              <strong>{{ overviewStats.threats?.alerted_hosts ?? 0 }}</strong>
              <small>Agent <b>{{ overviewStats.agents?.online ?? onlineCount }}</b> · VA <b>0</b></small>
            </div>
          </article>
          <article class="ov-rail-card click" @click="goPage('malware')">
            <div class="ov-rail-ico file">📁</div>
            <div class="ov-rail-body">
              <span>检出恶意文件</span>
              <strong>{{ overviewStats.threats?.malware_total ?? 0 }}</strong>
              <small>已处置 <b class="ok">{{ overviewStats.threats?.malware_handled ?? 0 }}</b></small>
            </div>
          </article>
          <article class="ov-rail-card click" @click="goEventsWith({ focus: 'process' })">
            <div class="ov-rail-ico endpoint">🛡</div>
            <div class="ov-rail-body">
              <span>终端威胁</span>
              <strong>{{ overviewStats.threats?.endpoint_total ?? 0 }}</strong>
              <small>已处置 <b class="ok">{{ overviewStats.threats?.endpoint_handled ?? 0 }}</b>
                <template v-if="overviewStats.threats?.endpoint_need_auth"> · 待跟进 {{ overviewStats.threats.endpoint_need_auth }}</template>
              </small>
            </div>
          </article>
          <article class="ov-rail-card click" @click="goEventsWith({ focus: 'network' })">
            <div class="ov-rail-ico net">🌐</div>
            <div class="ov-rail-body">
              <span>外连威胁</span>
              <strong>{{ overviewStats.threats?.external_total ?? 0 }}</strong>
              <small>已处置 <b class="ok">{{ overviewStats.threats?.external_handled ?? 0 }}</b></small>
            </div>
          </article>
        </div>

        <div class="ov-body">
          <div class="panel ov-threats">
            <div class="panel-hd">
              <div>
                <h3>最近威胁</h3>
                <span class="meta">点击进入威胁视图处置</span>
              </div>
              <div class="hd-right">
                <button type="button" class="btn-text" @click="goMenu('behaviors')">检出行为</button>
                <button type="button" class="btn-text" @click="goPage('events')">全部 →</button>
              </div>
            </div>
            <div v-if="recentThreats.length" class="table-scroll ov-threat-scroll">
              <table class="evt-table">
                <thead>
                  <tr>
                    <th>级别</th>
                    <th>事件</th>
                    <th>主机</th>
                    <th>模块</th>
                    <th>时间</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="e in recentThreats"
                    :key="e.id"
                    class="row-click"
                    @click="openEvent(e)"
                  >
                    <td><span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span></td>
                    <td class="strong">{{ e.title }}</td>
                    <td>{{ e.hostname || short(e.agent_id) }}</td>
                    <td class="muted">{{ modLabel(e.module) || '—' }}</td>
                    <td class="mono">{{ fmtTime(e.updated_at || e.created_at) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-else-if="recentRiskTimeline.length" class="table-scroll ov-threat-scroll">
              <p class="hint" style="margin:8px 14px">暂无正式威胁事件，以下为近期中高危时间线</p>
              <table class="evt-table">
                <thead>
                  <tr><th>级别</th><th>摘要</th><th>主机</th><th>类型</th><th>时间</th></tr>
                </thead>
                <tbody>
                  <tr
                    v-for="t in recentRiskTimeline"
                    :key="t.id || (t.ts + t.summary)"
                    class="row-click"
                    @click="openTimelineFor(t.agent_id)"
                  >
                    <td><span class="sev" :data-s="t.severity">{{ sevLabel(t.severity) }}</span></td>
                    <td class="strong">{{ cleanSummary(t.summary) }}</td>
                    <td>{{ t.hostname || short(t.agent_id) }}</td>
                    <td class="muted">{{ etypeLabel(t.etype) }}</td>
                    <td class="mono">{{ fmtTime(t.ts) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div v-else class="empty sm ov-empty">
              <p>暂无威胁事件</p>
              <p v-if="!agents.length" class="hint sm">尚未接入终端，可前往 <button type="button" class="btn-text" @click="goMenu('deploy')">部署安装</button> 纳管第一台主机。</p>
              <button type="button" class="btn sm" @click="goMenu('timeline')">查看时间线</button>
            </div>
          </div>

          <aside class="panel ov-side">
            <div class="panel-hd">
              <h3>终端</h3>
              <button type="button" class="btn-text" @click="goPage('hosts')">管理 →</button>
            </div>
            <div class="ov-host-summary">
              <div><b>{{ onlineCount }}</b><span>在线</span></div>
              <div><b>{{ agents.length - onlineCount }}</b><span>离线</span></div>
              <div><b>{{ agents.reduce((n, a) => n + (alertCount(a.agent_id) || 0), 0) }}</b><span>告警</span></div>
            </div>
            <div class="ov-host-list">
              <button
                v-for="a in agents"
                :key="a.agent_id"
                type="button"
                class="ov-host-row"
                @click="openHost(a, 'hosts')"
              >
                <i :class="['dot', a.online ? 'on' : '']" />
                <div class="ov-host-main">
                  <b>{{ a.hostname || short(a.agent_id) }}</b>
                  <small>{{ a.ip || '—' }} · v{{ a.version || '—' }} · {{ a.online ? '在线' : '离线' }}</small>
                </div>
                <span v-if="alertCount(a.agent_id)" class="alert-n badge">{{ alertCount(a.agent_id) }}</span>
                <span v-else class="ov-host-ok">正常</span>
              </button>
              <p v-if="!agents.length" class="empty sm">暂无终端</p>
            </div>
            <div class="ov-ops-mini">
              <div class="ov-ops-hd">
                <b>采集与下发</b>
                <button type="button" class="btn-text sm" @click="setSection('rules')">端上能力 →</button>
              </div>
              <dl class="ov-ops-dl">
                <div><dt>sync_rev</dt><dd class="mono">{{ agentSyncManifest?.sync_rev ?? '—' }}</dd></div>
                <div><dt>采集异常</dt><dd>{{ overviewStats.agents?.degraded_capture ?? 0 }} 台在线</dd></div>
                <div>
                  <dt>组件漂移</dt>
                  <dd>
                    <button
                      type="button"
                      class="btn-text"
                      :class="{ warn: (overviewStats.agents?.component_drift ?? 0) > 0 }"
                      @click="goMenu('upgrade')"
                    >
                      {{ overviewStats.agents?.component_drift ?? 0 }} 台
                    </button>
                  </dd>
                </div>
                <div><dt>策略未收敛</dt><dd>{{ overviewStats.agents?.policy_drift ?? 0 }} 台在线</dd></div>
                <div><dt>威胁事件</dt><dd>{{ allEvents.length }} 条</dd></div>
              </dl>
              <p v-if="ovDriftHint" class="hint sm ov-cap-hint warn-line">{{ ovDriftHint }}</p>
              <p v-else-if="ovOnlineCaptureHint" class="hint sm ov-cap-hint">{{ ovOnlineCaptureHint }}</p>
            </div>
            <div class="ov-side-links">
              <button type="button" class="btn sm" @click="goMenu('deploy')">部署安装</button>
              <button type="button" class="btn sm" @click="goMenu('hunt')">调查狩猎</button>
              <button type="button" class="btn sm" @click="goMenu('policy')">EDR 策略</button>
              <button type="button" class="btn sm" @click="goMenu('attck')">ATT&CK</button>
            </div>
          </aside>
        </div>

        <div class="ov-bottom-grid">
          <div class="panel ov-panel">
            <div class="panel-hd"><h3>威胁分类</h3><button type="button" class="btn-text" @click="goPage('events')">威胁事件 →</button></div>
            <div class="ov-cats ov-cats-compact">
              <button v-for="c in focusCats" :key="c.key" type="button" class="ov-cat" @click="goEventsWith({ focus: c.key })">
                <span class="focus-ico" :style="{ background: c.color }">{{ c.short }}</span>
                <b>{{ c.label }}</b>
                <em>{{ c.count }}</em>
              </button>
            </div>
          </div>

          <div class="panel ov-panel">
            <div class="panel-hd"><h3>告警级别</h3><span class="meta">未处置 {{ ovStatus.open }} · 已处置 {{ ovStatus.closed }}</span></div>
            <div class="ov-bars">
              <div v-for="s in ovSevDist" :key="s.key" class="ov-bar-row">
                <span class="sev" :data-s="s.key">{{ s.label }}</span>
                <div class="ov-bar"><i :style="{ width: s.pct + '%' }" :data-s="s.key" /></div>
                <b>{{ s.count }}</b>
              </div>
            </div>
          </div>

          <div class="panel ov-panel">
            <div class="panel-hd"><h3>近 7 天告警趋势</h3><span class="meta">共 {{ ovTrend.total }} 条</span></div>
            <div class="ov-trend">
              <div v-for="d in ovTrend.days" :key="d.day" class="ov-trend-col" :title="`${d.day}：${d.count} 条（高危 ${d.high}）`">
                <em>{{ d.count || '' }}</em>
                <div class="ov-trend-bar"><i :style="{ height: d.pct + '%' }" /><i class="hi" :style="{ height: d.hpct + '%' }" /></div>
                <small>{{ d.label }}</small>
              </div>
            </div>
          </div>

          <div class="panel ov-panel">
            <div class="panel-hd">
              <h3>{{ overviewTopMalware.length ? 'TOP5 恶意文件' : '风险终端 Top 5' }}</h3>
              <button type="button" class="btn-text" @click="overviewTopMalware.length ? goPage('malware') : goPage('hosts')">{{ overviewTopMalware.length ? '全部 →' : '终端列表 →' }}</button>
            </div>
            <ul v-if="overviewTopMalware.length" class="ov-mal-list compact">
              <li v-for="(m, i) in overviewTopMalware" :key="i">
                <i>{{ i + 1 }}</i><span class="mono" :title="m.title">{{ m.title }}</span><em>{{ m.count }}</em>
              </li>
            </ul>
            <div v-else class="ov-rank">
              <button v-for="(h, i) in ovTopHosts" :key="h.agent_id" type="button" class="ov-rank-row" @click="goEventsWith({ agent: h.agent_id })">
                <i>{{ i + 1 }}</i>
                <b>{{ h.hostname }}</b>
                <span v-if="h.high" class="sev" data-s="high">高危 {{ h.high }}</span>
                <em>{{ h.count }} 条</em>
              </button>
              <p v-if="!ovTopHosts.length" class="empty sm">暂无数据</p>
            </div>
          </div>
        </div>
      </section>

      <!-- ========== 主机时间线 ========== -->
      <section v-else-if="page === 'timeline'" class="page timeline-page">
        <header class="page-hd">
          <div>
            <h1>主机时间线</h1>
            <p class="desc">进程创建 / 退出、文件落地等近实时事件 · 共 {{ filteredTimeline.length }} 条</p>
          </div>
          <div class="hd-right">
            <select v-model="tlAgentId" class="search" @change="loadTimeline">
              <option value="">全部终端</option>
              <option v-for="a in agents" :key="a.agent_id" :value="a.agent_id">{{ a.hostname || short(a.agent_id) }}</option>
            </select>
            <input v-model="tlQ" class="search" placeholder="搜索摘要 / 路径 / PID…" @keyup.enter="loadTimeline" />
            <button type="button" class="btn primary" @click="loadTimeline">查询</button>
          </div>
        </header>

        <div class="tl-filters">
          <button
            type="button"
            class="tl-fchip"
            :class="{ on: !tlTypeFilter }"
            @click="tlTypeFilter = ''"
          >全部 <em>{{ timelineTotal }}</em></button>
          <button
            v-for="f in tlTypeOptions"
            :key="f.key"
            type="button"
            class="tl-fchip"
            :class="{ on: tlTypeFilter === f.key }"
            :data-k="f.key"
            @click="tlTypeFilter = tlTypeFilter === f.key ? '' : f.key"
          >{{ f.label }} <em>{{ f.count }}</em></button>
        </div>
        <p class="tl-hint">已过滤 Agent 自身采集命令及同一进程的重复记录；分类计数为全部数据，列表显示最近 300 条。点卡片「详情」查看完整字段。</p>

        <div class="tl-board" v-if="filteredTimeline.length">
          <div class="tl-rail">
            <article
              v-for="t in pagedTimeline"
              :key="t.id"
              class="tl-card"
              :data-s="t.severity"
              :data-k="etypeKind(t.etype)"
              :class="{ open: tlOpenId === t.id }"
            >
              <div class="tl-axis">
                <i class="tl-dot" />
                <span class="tl-line" />
              </div>
              <div class="tl-main" @click="tlOpenId = tlOpenId === t.id ? null : t.id">
                <header class="tl-card-hd">
                  <time>{{ fmtTime(t.ts || t.created_at) }}</time>
                  <span class="tl-etype" :data-k="etypeKind(t.etype)">{{ etypeLabel(t.etype) }}</span>
                  <span class="sev" :data-s="t.severity">{{ sevLabel(t.severity) }}</span>
                  <span class="tl-host">{{ t.hostname || short(t.agent_id) }}</span>
                  <button type="button" class="tl-expand" :aria-expanded="tlOpenId === t.id">
                    {{ tlOpenId === t.id ? '收起' : '详情' }}
                  </button>
                </header>
                <h3 class="tl-title">{{ t.summary }}</h3>
                <div class="tl-preview" v-if="detailPreview(t).length">
                  <span v-for="p in detailPreview(t)" :key="p.k" class="tl-chip">
                    <em>{{ p.k }}</em>{{ p.v }}
                  </span>
                </div>
                <div class="tl-fields" v-if="tlOpenId === t.id" @click.stop>
                  <template v-if="detailGroupsTl(t).length">
                    <section v-for="g in detailGroupsTl(t)" :key="g.title" class="tl-g">
                      <h5>{{ g.title }}<em>{{ g.items.length }}</em></h5>
                      <div class="tl-g-grid">
                        <div v-for="row in g.items" :key="row.key || row.k" class="tl-field" :class="{ wide: row.wide }">
                          <label>{{ row.k }}</label>
                          <div class="tl-fv">
                            <span :title="row.v" :class="{ mono: row.mono }">{{ row.v }}</span>
                            <button v-if="row.wide || row.mono" type="button" class="ev-copy" @click="copyText(row.v)">复制</button>
                          </div>
                        </div>
                      </div>
                    </section>
                  </template>
                  <p v-else class="tl-empty">该事件未携带明细字段（来源 {{ etypeLabel(t.etype) }}）</p>
                  <details v-if="parseTlDetail(t)" class="tl-raw">
                    <summary>原始明细 JSON</summary>
                    <pre>{{ JSON.stringify(parseTlDetail(t), null, 2) }}</pre>
                  </details>
                  <div class="tl-acts">
                    <button type="button" class="btn sm" @click="openTimelineHost(t)">打开主机快照</button>
                    <button v-if="tlPid(t)" type="button" class="btn sm" @click="openTimelineHostPid(t)">定位进程 PID {{ tlPid(t) }}</button>
                    <button v-if="t.agent_id" type="button" class="btn sm" @click="openTimelineThreats(t)">相关威胁</button>
                  </div>
                </div>
              </div>
            </article>
          </div>
          <div class="list-pager tl-pager">
            <span class="pg-info">第 {{ tlPage }} / {{ tlPageCount }} 页 · 共 {{ filteredTimeline.length }} 条</span>
            <div class="pg-acts">
              <select v-model.number="tlPageSize" class="pg-size" @change="tlPage = 1">
                <option :value="10">10 条/页</option>
                <option :value="20">20 条/页</option>
                <option :value="50">50 条/页</option>
              </select>
              <button type="button" class="btn sm" :disabled="tlPage <= 1" @click="tlPage--">上一页</button>
              <button type="button" class="btn sm" :disabled="tlPage >= tlPageCount" @click="tlPage++">下一页</button>
            </div>
          </div>
        </div>
        <div v-else class="panel pad">
          <p class="empty">暂无时间线事件。请确认终端已安装 Agent 且在线上报。</p>
        </div>
      </section>

      <!-- ========== 日志调查 ========== -->
      <section v-else-if="page === 'investigate'" class="page inv-page">
        <header class="inv-top">
          <div class="inv-tabs">
            <button type="button" class="inv-tab brand">日志调查</button>
            <button type="button" class="inv-tab on">新建查询</button>
          </div>
          <div class="inv-top-acts">
            <button type="button" class="btn sm" @click="saveInvQuery" :disabled="!invQ && !invFilters.hostname">保存</button>
            <button type="button" class="btn sm" @click="invShowSaved = !invShowSaved">已保存查询列表</button>
            <button type="button" class="btn sm" @click="invShowHist = !invShowHist">历史查询列表</button>
            <span class="inv-range-lab">时间范围：</span>
            <select v-model="invRange" class="search" @change="runInvestigate">
              <option value="1h">近 1 小时</option>
              <option value="today">今天</option>
              <option value="7d">近 7 天</option>
              <option value="30d">近 30 天</option>
              <option value="all">全部</option>
            </select>
            <span class="muted">刷新频率：关闭</span>
          </div>
        </header>

        <div v-if="invShowSaved || invShowHist" class="inv-saved panel pad">
          <template v-if="invShowSaved">
            <h4>已保存查询</h4>
            <button v-for="(s, i) in invSaved" :key="'s'+i" type="button" class="inv-saved-row" @click="applyInvSaved(s)">
              <b>{{ s.name }}</b><small>{{ s.q || '（仅筛选）' }}</small>
            </button>
            <p v-if="!invSaved.length" class="empty sm">暂无保存</p>
          </template>
          <template v-if="invShowHist">
            <h4>历史查询</h4>
            <button v-for="(s, i) in invHistory" :key="'h'+i" type="button" class="inv-saved-row" @click="applyInvSaved(s)">
              <b>{{ s.at }}</b><small>{{ s.q || s.hostname || '全部' }}</small>
            </button>
            <p v-if="!invHistory.length" class="empty sm">暂无历史</p>
          </template>
        </div>

        <div class="inv-filters panel">
          <div class="inv-fg inv-fg-2">
            <label>事件性质
              <select v-model="invFilters.nature">
                <option value="">全部</option>
                <option value="threat">威胁行为</option>
                <option value="risk">风险行为</option>
                <option value="minor">细微行为</option>
                <option value="surface">攻击面</option>
              </select>
            </label>
            <label>动作类型
              <select v-model="invFilters.etype">
                <option value="">全部</option>
                <option v-for="e in (invFacets.etype || [])" :key="e.id" :value="e.id">{{ etypeLabel(e.id) }} ({{ e.count }})</option>
              </select>
            </label>
            <label>终端名称
              <select v-model="invFilters.hostname">
                <option value="">全部</option>
                <option v-for="h in (invFacets.hostname || [])" :key="h.id" :value="h.id">{{ h.id }} ({{ h.count }})</option>
              </select>
            </label>
            <label>操作系统类型
              <select v-model="invFilters.os">
                <option value="">全部</option>
                <option v-for="os in bhOsOptions" :key="'inv-'+os" :value="os">{{ os }}</option>
              </select>
            </label>
          </div>
          <div v-show="invMoreFilters" class="inv-fg inv-fg-2 inv-more-panel">
            <label>目标实体
              <input v-model="invFilters.entity" class="field" placeholder="全部" />
            </label>
            <label>进程 / 文件路径
              <input v-model="invFilters.path" class="field" placeholder="全部" />
            </label>
            <label>SHA256 / MD5
              <input v-model="invFilters.hash_q" class="field" placeholder="全部" />
            </label>
            <label>威胁阶段
              <select v-model="invFilters.tactic">
                <option value="">全部</option>
                <option v-for="(lab, key) in TACTIC_CN" :key="key" :value="key">{{ lab }}</option>
              </select>
            </label>
          </div>
          <div class="inv-search-row">
            <input
              v-model="invQ"
              class="search grow"
              placeholder="请输入终端名 / 命令行路径 / SHA256 / IP / 域名等常见字段检索"
              @keyup.enter="runInvestigate"
            />
            <button type="button" class="btn" :class="{ on: invMoreFilters }" @click="invMoreFilters = !invMoreFilters">{{ invMoreFilters ? '− 收起筛选' : '+ 更多筛选条件' }}</button>
            <label class="inv-check inv-hide-noise">
              <input v-model="invHideProcNoise" type="checkbox" @change="runInvestigate" />
              <em>隐藏普通进程创建</em>
            </label>
            <button type="button" class="btn primary" :disabled="invBusy" @click="runInvestigate">{{ invBusy ? '查询中…' : '查询' }}</button>
            <button type="button" class="btn" @click="resetInvestigate">重置</button>
          </div>
        </div>

        <div class="inv-chart panel">
          <div class="inv-chart-hd">
            <span>行为趋势</span>
            <div class="inv-legend">
              <i data-n="threat" />威胁行为
              <i data-n="risk" />风险行为
              <i data-n="minor" />终端行为
            </div>
          </div>
          <div class="inv-bars" v-if="invHist.length">
            <div v-for="b in invHist" :key="b.ts" class="inv-bar-col" :title="`${b.ts} · 共 ${b.total}`">
              <div class="inv-bar-stack">
                <span class="seg threat" :style="{ height: histSegH(b, 'threat') }" />
                <span class="seg risk" :style="{ height: histSegH(b, 'risk') }" />
                <span class="seg minor" :style="{ height: histSegH(b, 'minor') }" />
              </div>
              <em>{{ histTick(b.ts) }}</em>
            </div>
          </div>
          <p v-else class="empty sm inv-chart-empty">查询后显示时间分布</p>
        </div>

        <div class="inv-body panel">
          <div class="inv-cats">
            <button type="button" :class="{ on: !invNatureTab }" @click="setInvNature('')">全部 <em>{{ invCounts.all || 0 }}</em></button>
            <button type="button" :class="{ on: invNatureTab === 'threat' }" @click="setInvNature('threat')">威胁 <em>{{ invCounts.threat || 0 }}</em></button>
            <button type="button" :class="{ on: invNatureTab === 'risk' }" @click="setInvNature('risk')">风险 <em>{{ invCounts.risk || 0 }}</em></button>
            <button type="button" :class="{ on: invNatureTab === 'surface' }" @click="setInvNature('surface')">攻击面收敛 <em>{{ invCounts.surface || 0 }}</em></button>
            <button type="button" :class="{ on: invNatureTab === 'minor' }" @click="setInvNature('minor')">细微 <em>{{ invCounts.minor || 0 }}</em></button>
          </div>

          <div class="inv-layout" :class="{ open: !!invDetail }">
            <div class="inv-list">
              <p v-if="invBusy" class="hint sm inv-busy-hint">{{ invItems.length ? '刷新中…' : '加载中…' }}</p>
              <template v-if="invItems.length">
                <div class="inv-list-scroll" :class="{ dim: invBusy }">
                  <table>
                    <thead>
                      <tr>
                        <th>时间</th>
                        <th>性质</th>
                        <th>类型</th>
                        <th>摘要</th>
                        <th>主机</th>
                        <th>进程</th>
                        <th>路径 / 命令</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr
                        v-for="it in pagedInvItems"
                        :key="it.id"
                        class="row-click"
                        :class="{ active: invDetailId === it.id }"
                        @click="openInvDetail(it.id)"
                      >
                        <td class="mono">{{ fmtTime(it.ts) }}</td>
                        <td><span class="nat" :data-n="it.nature">{{ natureLabel(it.nature) }}</span></td>
                        <td>{{ etypeLabel(it.etype) }}</td>
                        <td class="strong" :title="cleanSummary(it.summary)">{{ cleanSummary(it.summary) }}</td>
                        <td>{{ it.hostname || short(it.agent_id) }}</td>
                        <td>{{ it.name || '—' }} <em v-if="it.pid" class="muted">#{{ it.pid }}</em></td>
                        <td class="muted mono" :title="it.command_line || it.path">{{ (it.command_line || it.path || '—').slice(0, 64) }}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                <div class="list-pager">
                  <span class="pg-info">第 {{ invPage }} / {{ invPageCount }} 页 · 共 {{ invItems.length }} 条</span>
                  <div class="pg-acts">
                    <select v-model.number="invPageSize" class="pg-size" @change="invPage = 1">
                      <option :value="10">10 条/页</option>
                      <option :value="20">20 条/页</option>
                      <option :value="50">50 条/页</option>
                    </select>
                    <button type="button" class="btn sm" :disabled="invPage <= 1" @click="invPage--">上一页</button>
                    <button type="button" class="btn sm" :disabled="invPage >= invPageCount" @click="invPage++">下一页</button>
                  </div>
                </div>
              </template>
              <p v-else-if="!invBusy" class="empty ov-empty">暂无日志。确认 Agent 在线上报时间线后会自动加载；也可点「查询」。</p>
              <p v-else class="empty ov-empty">正在拉取时间线…</p>
            </div>

            <aside v-if="invDetail" class="inv-detail">
              <div class="inv-dh">
                <div>
                  <b>{{ cleanSummary(invDetail.item?.summary) || '日志详情' }}</b>
                  <small>{{ fmtTime(invDetail.item?.ts) }} · {{ invDetail.item?.hostname || short(invDetail.item?.agent_id) }}</small>
                </div>
                <button type="button" class="icon-x" @click="closeInvDetail">×</button>
              </div>
              <div class="inv-dtabs">
                <button type="button" :class="{ on: invDetailTab === 'info' }" @click="invDetailTab = 'info'">详细信息</button>
                <button type="button" :class="{ on: invDetailTab === 'chain' }" @click="invDetailTab = 'chain'">进程链</button>
                <button v-if="invEntityId" type="button" :class="{ on: invDetailTab === 'entity' }" @click="openEntityTab">进程实体</button>
                <button type="button" :class="{ on: invDetailTab === 'raw' }" @click="invDetailTab = 'raw'">原始日志</button>
              </div>

              <div v-if="invDetailTab === 'entity'" class="inv-dbody">
                <p v-if="entityBusy" class="muted">加载中…</p>
                <p v-else-if="entityErr" class="empty sm">{{ entityErr }}</p>
                <template v-else-if="entityView">
                  <section class="inv-g">
                    <h5>
                      {{ entityView.entity?.name || '进程' }}
                      <em class="pill" :class="{ on: entityView.entity && !entityView.entity.exit_time }" style="margin-left:6px">
                        {{ entityView.entity?.exit_time ? '已退出（墓碑）' : '运行中/未见退出' }}
                      </em>
                    </h5>
                    <div class="inv-kv">
                      <div v-for="f in entityFieldsOf(entityView.entity)" :key="f.k" class="inv-kv-row" :class="{ wide: String(f.v).length > 48 }">
                        <span>{{ f.k }}</span><strong class="mono">{{ f.v }}</strong>
                      </div>
                    </div>
                  </section>
                  <section class="inv-g">
                    <h5>祖先链</h5>
                    <div class="inv-chain">
                      <div v-for="a in [...(entityView.ancestors || [])].reverse()" :key="a.entity_id" class="inv-cnode" :class="{ miss: a.missing }">
                        <i class="dot" />
                        <div>
                          <b class="ent-link" @click="loadEntity(a.entity_id)">{{ a.missing ? '（未记录的祖先）' : (a.name || ('PID ' + a.pid)) }}</b>
                          <span v-if="!a.missing">PID {{ a.pid }} · {{ fmtTime(a.create_time) }}</span>
                          <small v-if="a.command_line" class="mono">{{ a.command_line }}</small>
                        </div>
                      </div>
                      <div class="inv-cnode on">
                        <i class="dot" />
                        <div><b>{{ entityView.entity?.name || '当前进程' }}</b><span>PID {{ entityView.entity?.pid }}</span></div>
                      </div>
                      <div v-for="c in (entityView.children || [])" :key="c.entity_id" class="inv-cnode child">
                        <i class="dot" />
                        <div>
                          <b class="ent-link" @click="loadEntity(c.entity_id)">{{ c.name || ('PID ' + c.pid) }}</b>
                          <span>PID {{ c.pid }} · {{ fmtTime(c.create_time) }}{{ c.exit_time ? ' · 已退出' : '' }}</span>
                        </div>
                      </div>
                    </div>
                  </section>
                  <section class="inv-g">
                    <h5>归属事件（{{ (entityView.events || []).length }}）</h5>
                    <div class="health-chips" style="margin-bottom:6px">
                      <span v-for="(n, k) in (entityView.event_counts || {})" :key="k" class="hchip">{{ etypeLabel(k) }} {{ n }}</span>
                    </div>
                    <div v-for="ev in (entityView.events || []).slice(0, 120)" :key="ev.id" class="ent-ev">
                      <span class="muted">{{ fmtTime(ev.ts) }}</span>
                      <em class="pill" :class="'sev-' + ev.severity">{{ etypeLabel(ev.etype) }}</em>
                      <span>{{ cleanSummary(ev.summary) }}</span>
                    </div>
                    <p v-if="!(entityView.events || []).length" class="empty sm">该实体暂无其他归属事件</p>
                  </section>
                </template>
              </div>

              <div v-else-if="invDetailTab === 'info'" class="inv-dbody">
                <section class="inv-g">
                  <h5>日志信息</h5>
                  <div class="inv-kv">
                    <div v-for="f in (invDetail.info || [])" :key="f.k" class="inv-kv-row">
                      <span>{{ f.k }}</span>
                      <strong>{{ f.k === '摘要' ? cleanSummary(f.v) : (f.v == null || f.v === '' ? '—' : f.v) }}</strong>
                    </div>
                  </div>
                </section>
                <section v-for="g in (invDetail.groups || [])" :key="g.title" class="inv-g">
                  <h5>{{ g.title }}</h5>
                  <div class="inv-kv">
                    <div v-for="f in g.fields" :key="f.k" class="inv-kv-row" :class="{ wide: String(f.v).length > 48 }">
                      <span>{{ DETAIL_LABELS[f.k] || colLabel(f.k) || f.k }}</span>
                      <strong class="mono">
                        {{ f.v }}
                        <button v-if="String(f.v).length > 24" type="button" class="ev-copy" @click="copyText(String(f.v))">复制</button>
                      </strong>
                    </div>
                  </div>
                </section>
                <div class="inv-dacts">
                  <button type="button" class="btn sm" @click="jumpInvTimeline">完整时间线</button>
                  <button type="button" class="btn sm" @click="jumpInvHost">打开主机</button>
                </div>
              </div>

              <div v-else-if="invDetailTab === 'chain'" class="inv-dbody">
                <div v-if="(invDetail.chain || []).length" class="inv-chain">
                  <div
                    v-for="(n, i) in invDetail.chain"
                    :key="i"
                    class="inv-cnode"
                    :class="{ on: n.current, miss: n.missing, child: n.child }"
                  >
                    <i class="dot" />
                    <div>
                      <b>{{ n.name || ('PID ' + n.pid) }}</b>
                      <span>PID {{ n.pid }}<template v-if="n.ppid != null"> · PPID {{ n.ppid }}</template></span>
                      <small v-if="n.path" class="mono">{{ n.path }}</small>
                      <small v-if="n.command_line" class="mono">{{ n.command_line }}</small>
                    </div>
                  </div>
                </div>
                <p v-else class="empty sm">该日志无进程 PID，或同主机时间线不足以还原父子链。</p>
              </div>

              <div v-else class="inv-dbody">
                <pre class="inv-raw">{{ JSON.stringify(invDetail.raw || invDetail.item, null, 2) }}</pre>
                <button type="button" class="btn sm" @click="copyText(JSON.stringify(invDetail.raw || invDetail.item, null, 2))">复制 JSON</button>
              </div>
            </aside>
          </div>
        </div>
      </section>

      <!-- ========== 全局狩猎 ========== -->
      <section v-else-if="page === 'hunt'" class="page">
        <header class="page-hd">
          <div>
            <h1>调查狩猎</h1>
            <p class="desc">跨主机搜索：时间线 / 快照 / 威胁事件（哈希、路径、命令行等）</p>
          </div>
        </header>
        <div class="panel pad">
          <div class="hunt-bar">
            <input v-model="huntQ" class="search grow" placeholder="输入 SHA256 / 路径 / 进程名 / 命令片段…" @keyup.enter="runHunt" />
            <button type="button" class="btn primary" :disabled="huntBusy" @click="runHunt">{{ huntBusy ? '搜索中…' : '搜索' }}</button>
          </div>
          <div class="hunt-quick">
            <button type="button" class="chip" @click="huntQ='powershell'; runHunt()">powershell</button>
            <button type="button" class="chip" @click="huntQ='\\\\temp\\\\'; runHunt()">\\temp\\</button>
            <button type="button" class="chip" @click="huntQ='NotSigned'; runHunt()">NotSigned</button>
            <button type="button" class="chip" @click="openHuntModule('process', 'temp')">快照·临时目录进程</button>
            <button type="button" class="chip" @click="openHuntModule('file', 'Public')">快照·Public 文件</button>
          </div>
          <table v-if="huntHits.length">
            <thead><tr><th>来源</th><th>标题</th><th>主机</th><th>模块</th><th>时间</th><th>片段</th></tr></thead>
            <tbody>
              <tr v-for="(h, i) in huntHits" :key="i" class="row-click" @click="openHuntHit(h)">
                <td><span class="tag">{{ h.source }}</span></td>
                <td class="strong">{{ h.title }}</td>
                <td>{{ h.hostname || short(h.agent_id) }}</td>
                <td>{{ modLabel(h.module) || h.module || '—' }}</td>
                <td>{{ fmtTime(h.ts) }}</td>
                <td class="muted" :title="h.snippet">{{ (h.snippet || '').slice(0, 80) }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else-if="huntDone" class="empty">无命中</p>
          <p v-else class="empty sm">输入关键词开始全网狩猎</p>
        </div>
      </section>

      <!-- ========== DNS 狩猎 ========== -->
      <section v-else-if="page === 'dns'" class="page dns-page">
        <header class="page-hd">
          <div>
            <h1>DNS 狩猎</h1>
            <p class="desc">按域名聚合：谁解析过某域名 / 应答 IP 反查 / 解析失败与 DGA；可筛情报命中外联</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn sm" :disabled="dnsBusy" @click="loadDns">{{ dnsBusy ? '刷新中…' : '刷新' }}</button>
            <button type="button" class="btn sm" @click="goMenu('events')">威胁事件 →</button>
          </div>
        </header>

        <div class="evt-filter-bar panel pad">
          <label class="evt-fl">
            <span>域名</span>
            <input v-model="dnsDomainQ" class="field mono" placeholder="example.com" @keyup.enter="applyDnsFilters" />
          </label>
          <label class="evt-fl">
            <span>应答 IP</span>
            <input v-model="dnsIpQ" class="field mono" placeholder="1.2.3.4" @keyup.enter="applyDnsFilters" />
          </label>
          <label class="evt-fl">
            <span>进程</span>
            <input v-model="dnsProcQ" class="field" placeholder="powershell" @keyup.enter="applyDnsFilters" />
          </label>
          <label class="evt-fl">
            <span>终端</span>
            <select v-model="dnsAgent" class="field">
              <option value="">全部终端</option>
              <option v-for="a in agents" :key="a.agent_id" :value="a.agent_id">{{ a.hostname || short(a.agent_id) }}</option>
            </select>
          </label>
          <label class="evt-fl">
            <span>职场 / 分组</span>
            <select v-model="dnsGroupId" class="field">
              <option value="">全部</option>
              <option v-for="g in groupItems" :key="g.id" :value="g.id">{{ g.name }}</option>
            </select>
          </label>
          <label class="evt-fl chk-inline">
            <span>条件</span>
            <div class="dns-checks">
              <label class="chk"><input v-model="dnsNx" type="checkbox" /> 仅解析失败</label>
              <label class="chk"><input v-model="dnsDgaOnly" type="checkbox" /> 高 DGA</label>
              <label class="chk"><input v-model="dnsIntelOnly" type="checkbox" /> 情报命中</label>
            </div>
          </label>
          <div class="evt-fl-acts">
            <button type="button" class="btn primary" :disabled="dnsBusy" @click="applyDnsFilters">{{ dnsBusy ? '查询中…' : '查询' }}</button>
            <button type="button" class="btn" @click="resetDnsFilters">重置</button>
          </div>
        </div>

        <div class="dns-summary panel pad">
          <div class="mal-stat"><b>{{ dnsStats.total }}</b><span>域名聚合</span></div>
          <div class="mal-stat"><b>{{ dnsStats.hits }}</b><span>解析次数</span></div>
          <div class="mal-stat"><b>{{ dnsStats.nx }}</b><span>解析失败</span></div>
          <div class="mal-stat"><b>{{ dnsStats.intel }}</b><span>情报命中</span></div>
          <p class="hint sm">
            情报源：<code class="mono">{{ dnsIocMeta.path || 'ioc_data.db' }}</code>
            <template v-if="dnsIocMeta.ok === false">
              · <span class="off">{{ dnsIocMeta.hint || '未加载' }}</span>
            </template>
            <template v-else>
              · 精确匹配域名 / ip_only
              <template v-if="dnsIocMeta.ms != null">（{{ dnsIocMeta.ms }}ms）</template>
            </template>
            ；点「次数」下钻日志，点域名筛威胁事件
          </p>
        </div>

        <div class="panel pad dns-table-panel">
          <p v-if="dnsBusy && !filteredDnsItems.length" class="hint sm" style="margin:0 0 8px">加载中…</p>
          <template v-if="filteredDnsItems.length">
            <div class="table-scroll dns-table-scroll">
              <table class="evt-table">
                <thead>
                  <tr>
                    <th class="sortable" @click="toggleDnsSort('domain')">域名 <i class="sort-ico">{{ dnsSortMark('domain') }}</i></th>
                    <th>主机</th>
                    <th class="sortable" @click="toggleDnsSort('hits')">次数 <i class="sort-ico">{{ dnsSortMark('hits') }}</i></th>
                    <th class="sortable" @click="toggleDnsSort('nx_hits')">失败 <i class="sort-ico">{{ dnsSortMark('nx_hits') }}</i></th>
                    <th class="sortable" @click="toggleDnsSort('max_dga')">DGA <i class="sort-ico">{{ dnsSortMark('max_dga') }}</i></th>
                    <th>情报</th>
                    <th>进程</th>
                    <th>应答</th>
                    <th class="sortable" @click="toggleDnsSort('first_seen')">首次 <i class="sort-ico">{{ dnsSortMark('first_seen') }}</i></th>
                    <th class="sortable" @click="toggleDnsSort('last_seen')">最近 <i class="sort-ico">{{ dnsSortMark('last_seen') }}</i></th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="d in pagedDnsItems"
                    :key="d.agent_id + ':' + d.domain"
                    class="row-click"
                    :class="{ 'row-warn': d.nx_hits > 0 || d.max_dga >= 0.7 || d.ioc_hit }"
                    @click="openDnsThreat(d)"
                  >
                    <td class="strong mono" :title="d.domain">{{ d.domain }}</td>
                    <td>{{ d.hostname || short(d.agent_id) }}</td>
                    <td @click.stop>
                      <button
                        type="button"
                        class="log-n"
                        :class="{ hot: Number(d.hits) > 5, multi: Number(d.hits) >= 20 }"
                        :title="`解析 ${d.hits || 0} 次 · 点击查看相关日志`"
                        @click="openDnsLogHits(d)"
                      >{{ d.hits || 0 }}</button>
                    </td>
                    <td>{{ d.nx_hits || '' }}</td>
                    <td>{{ d.max_dga ? Number(d.max_dga).toFixed(2) : '' }}</td>
                    <td>
                      <span
                        v-if="d.ioc_hit"
                        class="tag judge"
                        :title="dnsIocTitle(d)"
                      >{{ dnsIocLabel(d) }}</span>
                      <span v-else class="muted">—</span>
                    </td>
                    <td class="muted" :title="(d.processes || []).join(', ')">{{ (d.processes || []).slice(0, 2).join(', ') }}{{ (d.processes || []).length > 2 ? '…' : '' }}</td>
                    <td class="mono muted" :title="(d.answers || []).join('\n')">{{ (d.answers || []).slice(0, 3).join(', ') }}{{ (d.answers || []).length > 3 ? '…' : '' }}</td>
                    <td class="muted">{{ fmtTime(d.first_seen) }}</td>
                    <td class="muted">{{ fmtTime(d.last_seen) }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="list-pager dns-pager">
              <span class="pg-info">第 {{ dnsPage }} / {{ dnsPageCount }} 页 · 共 {{ filteredDnsItems.length }} 条</span>
              <div class="pg-acts">
                <select v-model.number="dnsPageSize" class="pg-size" @change="dnsPage = 1">
                  <option :value="10">10 条/页</option>
                  <option :value="20">20 条/页</option>
                  <option :value="50">50 条/页</option>
                </select>
                <button type="button" class="btn sm" :disabled="dnsPage <= 1" @click="dnsPage--">上一页</button>
                <button type="button" class="btn sm" :disabled="dnsPage >= dnsPageCount" @click="dnsPage++">下一页</button>
              </div>
            </div>
          </template>
          <div v-else-if="!dnsBusy" class="empty ov-empty">
            <p>{{ dnsHasFilter ? '当前筛选下无 DNS 记录' : '暂无 DNS 记录（需要 0.11+ Agent 且 ETW 原生会话可用）' }}</p>
            <div class="row" style="justify-content:center;gap:8px;flex-wrap:wrap">
              <button v-if="dnsHasFilter" type="button" class="btn sm" @click="resetDnsFilters">清除筛选</button>
              <button type="button" class="btn sm" @click="loadDns">重新加载</button>
            </div>
          </div>
        </div>
      </section>

      <!-- ========== 检出行为（图三看板） ========== -->
      <section v-else-if="page === 'behaviors'" class="page behaviors-page">
        <header class="bh-top">
          <h1>检出行为</h1>
          <div class="bh-top-r">
            <span class="muted">时间范围：全部</span>
            <button type="button" class="btn sm" @click="goPage('events')">威胁事件 →</button>
          </div>
        </header>

        <div class="bh-filters panel">
          <select v-model="bhNature" class="search">
            <option value="">事件性质：全部</option>
            <option value="threat">威胁行为</option>
            <option value="risk">风险行为</option>
          </select>
          <select v-model="bhGroup" class="search">
            <option value="">职场 / 分组：全部</option>
            <option v-for="g in groupItems" :key="g.id" :value="g.id">{{ g.name }}</option>
          </select>
          <select v-model="bhOs" class="search">
            <option value="">操作系统：全部</option>
            <option v-for="os in bhOsOptions" :key="os" :value="os">{{ os }}</option>
          </select>
          <select v-model="behaviorSev" class="search">
            <option value="">严重级别：全部</option>
            <option value="critical">严重</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
          <input v-model="bhQ" class="search grow" placeholder="终端名 / 告警标题 / 路径…" @keyup.enter="bhPage = 1" />
          <select v-model="bhTactic" class="search">
            <option value="">ATT&CK 阶段：全部</option>
            <option v-for="(lab, key) in TACTIC_CN" :key="key" :value="key">{{ lab }}</option>
          </select>
          <button type="button" class="btn primary" @click="bhPage = 1">查询</button>
          <button type="button" class="btn" @click="resetBhFilters">重置</button>
        </div>

        <div class="bh-stats">
          <div class="panel bh-sev">
            <div class="panel-hd bare"><h3>严重级别分布</h3></div>
            <div class="bh-sev-body">
              <div class="bh-sev-row">
                <span class="bh-ico threat">威</span>
                <div class="bh-sev-main">
                  <b>威胁行为 <em>{{ bhThreatN }}</em></b>
                  <div class="bh-bar"><i class="threat" :style="{ width: bhBarPct(bhThreatN) + '%' }" /></div>
                  <small>明确威胁，可进行处置</small>
                </div>
              </div>
              <div class="bh-sev-row">
                <span class="bh-ico risk">险</span>
                <div class="bh-sev-main">
                  <b>风险行为 <em>{{ bhRiskN }}</em></b>
                  <div class="bh-bar"><i class="risk" :style="{ width: bhBarPct(bhRiskN) + '%' }" /></div>
                  <small>可疑行为，用于溯源和关联</small>
                </div>
              </div>
            </div>
          </div>

          <div class="panel bh-stage">
            <div class="panel-hd bare">
              <h3>威胁阶段分布</h3>
              <span class="meta">点击节点或图例筛选 · 已覆盖 {{ bhTacticHitN }} / 12</span>
            </div>
            <div class="bh-wave">
              <svg class="bh-wave-svg" viewBox="0 0 720 140" preserveAspectRatio="none" aria-hidden="true">
                <defs>
                  <linearGradient id="bhWaveGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stop-color="#f5c542" />
                    <stop offset="35%" stop-color="#f08a1f" />
                    <stop offset="65%" stop-color="#e11d2e" />
                    <stop offset="100%" stop-color="#94a3b8" />
                  </linearGradient>
                </defs>
                <path
                  class="bh-wave-path"
                  :d="bhWavePath"
                  fill="none"
                  stroke="url(#bhWaveGrad)"
                  stroke-width="22"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
              <button
                v-for="(t, i) in bhTacticRing"
                :key="'wn-' + t.key"
                type="button"
                class="bh-wave-node"
                :class="{ on: bhTactic === t.key, hit: t.count > 0, dim: !t.count }"
                :style="bhWaveNodeStyle(i, t)"
                :title="`${t.stageLabel}：${t.count}`"
                @click="bhTactic = bhTactic === t.key ? '' : t.key; bhPage = 1"
              >
                <svg class="bh-ico-svg" viewBox="0 0 24 24" aria-hidden="true">
                  <path :d="stageIconPath(t.icon)" fill="currentColor" />
                </svg>
              </button>
            </div>
            <div class="bh-wave-legend">
              <button
                v-for="(t, i) in bhTacticRing"
                :key="'wl-' + t.key"
                type="button"
                class="bh-leg"
                :class="{ on: bhTactic === t.key, hit: t.count > 0 }"
                @click="bhTactic = bhTactic === t.key ? '' : t.key; bhPage = 1"
              >
                <i :style="{ background: t.color }" />
                <span>{{ i + 1 }}-{{ t.stageLabel }}</span>
                <b>{{ t.count }}</b>
              </button>
            </div>
          </div>

          <div class="panel bh-top">
            <div class="panel-hd bare"><h3>TOP 检出威胁</h3></div>
            <div class="bh-top-list">
              <button
                v-for="(t, i) in bhTopThreats"
                :key="t.title"
                type="button"
                class="bh-top-row"
                @click="bhQ = t.title; bhPage = 1"
              >
                <em>{{ i + 1 }}</em>
                <div class="bh-top-main">
                  <b :title="t.title">{{ t.title }}</b>
                  <i class="bh-bar"><i :style="{ width: bhBarPct(t.count, bhTopMax) + '%' }" /></i>
                </div>
                <strong>{{ t.count }}</strong>
              </button>
              <p v-if="!bhTopThreats.length" class="empty sm">暂无</p>
            </div>
          </div>
        </div>

        <div class="bh-bottom">
          <aside class="panel bh-hosts">
            <div class="panel-hd bare">
              <h3>检出终端 ({{ bhHostList.length }})</h3>
            </div>
            <button type="button" class="term-all" :class="{ on: !bhAgentId }" @click="bhAgentId = ''">全部终端</button>
            <div class="bh-host-scroll">
              <button
                v-for="h in bhHostList"
                :key="h.agent_id"
                type="button"
                class="term-row"
                :class="{ on: bhAgentId === h.agent_id }"
                @click="bhAgentId = h.agent_id; bhPage = 1"
              >
                <i :class="['dot', h.online ? 'on' : '']" />
                <span>{{ h.hostname }}</span>
                <em class="alert-n">{{ h.count }}</em>
              </button>
            </div>
          </aside>

          <div class="panel bh-list">
            <div class="panel-hd bare">
              <h3>检出行为列表 ({{ behaviorEvents.length }})</h3>
              <span class="meta">点行下方看详情 · 「视」进威胁视图</span>
            </div>
            <div class="table-scroll" v-if="pagedBhEvents.length">
              <table class="evt-table">
                <thead>
                  <tr>
                    <th>行为 / 告警</th>
                    <th>级别</th>
                    <th>类型</th>
                    <th>终端</th>
                    <th>用户</th>
                    <th>时间</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <template v-for="e in pagedBhEvents" :key="e.id">
                    <tr class="row-click" :class="{ on: listFocusId === e.id }" @click="selectListEvent(e)">
                      <td class="strong">{{ e.title }}</td>
                      <td><span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span></td>
                      <td><span class="tag judge">{{ behaviorKind(e) }}</span></td>
                      <td>{{ e.hostname || short(e.agent_id) }}</td>
                      <td>{{ eventUserHint(e) }}</td>
                      <td>{{ fmtTime(e.updated_at || e.created_at) }}</td>
                      <td class="ops" @click.stop>
                        <button type="button" class="op-ico primary" title="威胁视图" @click="openEvent(e)">视</button>
                      </td>
                    </tr>
                    <tr v-if="listFocusId === e.id && listFocusEvent" class="evt-expand-row">
                      <td colspan="7">
                        <div class="evt-inline">
                          <div class="ep-hd">
                            <div class="ep-title">
                              <span class="sev" :data-s="listFocusEvent.severity">{{ sevLabel(listFocusEvent.severity) }}</span>
                              <b>{{ listFocusEvent.title }}</b>
                            </div>
                            <div class="ep-acts">
                              <button type="button" class="btn sm primary" @click.stop="openEvent(listFocusEvent)">威胁视图 →</button>
                              <button type="button" class="btn sm" @click.stop="openAllow(listFocusEvent)">加白</button>
                              <button type="button" class="btn-text" @click.stop="clearListFocus">收起</button>
                            </div>
                          </div>
                          <div class="bh-expand">
                            <section class="bh-expand-card">
                              <header class="bh-expand-hd">影响终端 / 用户</header>
                              <div class="ed-host-grid">
                                <div class="ed-host-cell">
                                  <span class="ed-k">终端</span>
                                  <div class="ed-host-name">
                                    <i :class="['dot', listFocusAgent?.online ? 'on' : '']" />
                                    <b>{{ listFocusEvent.hostname || listFocusAgent?.hostname || short(listFocusEvent.agent_id) }}</b>
                                    <em :class="listFocusAgent?.online ? 'on' : 'off'">{{ listFocusAgent?.online ? '在线' : '离线' }}</em>
                                  </div>
                                  <div class="ed-host-sub">
                                    <span>IP {{ listFocusAgent?.ip || agentIp(listFocusEvent.agent_id) || '—' }}</span>
                                    <span v-if="listFocusMac">MAC {{ listFocusMac }}</span>
                                  </div>
                                </div>
                                <div class="ed-host-cell">
                                  <span class="ed-k">用户</span>
                                  <div class="ed-user">
                                    <b>{{ listFocusUser || '未知用户' }}</b>
                                    <small v-if="listFocusUserDomain">{{ listFocusUserDomain }}</small>
                                    <small v-else>分组 {{ listFocusGroupLabel }}</small>
                                  </div>
                                </div>
                              </div>
                              <div class="ed-kv bh-expand-kv">
                                <div><span>操作系统</span><b>{{ listFocusOsLabel }}</b></div>
                                <div><span>Agent ID</span><b class="mono">{{ listFocusEvent.agent_id || '—' }}</b></div>
                                <div><span>检测模块</span><b>{{ modLabel(listFocusEvent.module) || '—' }}</b></div>
                                <div><span>判定</span><b>{{ judgeOf(listFocusEvent) }}</b></div>
                              </div>
                            </section>
                            <section class="bh-expand-card bh-expand-main">
                              <header class="bh-expand-hd">
                                行为详情
                                <button v-if="listOverviewExtra.length" type="button" class="ed-more" @click.stop="edMore = !edMore">
                                  {{ edMore ? '收起额外字段' : `展开额外字段（${listOverviewExtra.length}）` }}
                                </button>
                              </header>
                              <div class="bh-field-grid">
                                <div
                                  v-for="r in listBehaviorDetailRows"
                                  :key="'bh-' + r.k"
                                  class="bh-field"
                                  :class="{ wide: r.mono || String(r.v).length > 48, root: r.root }"
                                >
                                  <span>{{ r.k }}</span>
                                  <b :class="{ mono: r.mono }" :title="r.v">{{ r.v }}</b>
                                </div>
                              </div>
                            </section>
                          </div>
                        </div>
                      </td>
                    </tr>
                  </template>
                </tbody>
              </table>
            </div>
            <p v-else class="empty">暂无检出行为</p>
            <div v-if="behaviorEvents.length" class="list-pager">
              <span class="pg-info">第 {{ bhPage }} / {{ bhPageCount }} 页 · 共 {{ behaviorEvents.length }} 条</span>
              <div class="pg-acts">
                <select v-model.number="bhPageSize" class="pg-size" @change="bhPage = 1">
                  <option :value="10">10 条/页</option>
                  <option :value="20">20 条/页</option>
                  <option :value="50">50 条/页</option>
                </select>
                <button type="button" class="btn sm" :disabled="bhPage <= 1" @click="bhPage--">上一页</button>
                <button type="button" class="btn sm" :disabled="bhPage >= bhPageCount" @click="bhPage++">下一页</button>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- ========== 威胁事件 / 恶意文件 ========== -->
      <section v-else-if="page === 'events' || page === 'malware'" class="page events-page" :class="{ 'malware-page': page === 'malware' }">
        <header class="page-hd">
          <div>
            <h1>{{ page === 'malware' ? '恶意文件' : '威胁事件' }}</h1>
            <p class="desc">{{ page === 'malware'
              ? '文件落地、FIM 变更、带可执行路径/样本的告警（含「规则命中」类文件威胁）；点击行查看详情与隔离处置'
              : '点击行在右侧查看详情；点「打开威胁视图」进入处置页' }}</p>
          </div>
          <div class="hd-right">
            <span class="live-hint" :class="{ on: liveOk }"><i class="live-dot" />{{ liveOk ? liveAgo : '连接中' }}</span>
            <select v-if="page === 'malware'" v-model="eventSevFilter" class="search sev-filter">
              <option value="">全部级别</option>
              <option value="critical">严重</option>
              <option value="high">高危</option>
              <option value="medium">中危</option>
              <option value="low">低危</option>
            </select>
            <button
              v-if="selectedEventIds.length"
              type="button"
              class="btn danger"
              @click="removeSelectedEvents"
            >删除所选 ({{ selectedEventIds.length }})</button>
            <button
              v-if="isAdmin && filteredEvents.length"
              type="button"
              class="btn danger"
              @click="removeAllEvents"
            >{{ eventFiltersActive || page === 'malware' ? '删除筛选结果' : '全部删除' }}</button>
          </div>
        </header>

        <div v-if="page === 'events'" class="evt-filter-bar panel pad">
          <label class="evt-fl">
            <span>威胁 / 域名</span>
            <input
              v-model="eventQName"
              class="field"
              placeholder="标题、域名、进程…"
              @keyup.enter="applyEventFilters"
            />
          </label>
          <label class="evt-fl">
            <span>职场 / 分组</span>
            <select v-model="eventGroupId" class="field">
              <option value="">全部</option>
              <option v-for="g in groupItems" :key="g.id" :value="g.id">{{ g.name }}</option>
            </select>
          </label>
          <label class="evt-fl">
            <span>严重级别</span>
            <select v-model="eventSevFilter" class="field">
              <option value="">全部</option>
              <option value="critical">严重</option>
              <option value="high">高危</option>
              <option value="medium">中危</option>
              <option value="low">低危</option>
            </select>
          </label>
          <label class="evt-fl">
            <span>威胁类型</span>
            <select v-model="eventTypeFilter" class="field">
              <option value="">全部</option>
              <option v-for="c in FOCUS_DEFS" :key="c.key" :value="c.key">{{ c.label }}</option>
            </select>
          </label>
          <label class="evt-fl grow">
            <span>情报 IP / 域名</span>
            <input
              v-model="eventIocQ"
              class="field mono"
              placeholder="外联 IP 或域名，如 1.2.3.4 / evil.com"
              @keyup.enter="applyEventFilters"
            />
          </label>
          <div class="evt-fl-acts">
            <button type="button" class="btn primary" @click="applyEventFilters">查询</button>
            <button type="button" class="btn" @click="resetEventFilters">重置</button>
          </div>
        </div>

        <div class="event-layout single">
          <div class="event-main">
            <div v-if="page === 'malware'" class="malware-summary panel pad">
              <div class="mal-stat">
                <b>{{ malwareFileStats.total }}</b>
                <span>文件相关告警</span>
              </div>
              <div class="mal-stat">
                <b>{{ malwareFileStats.hosts }}</b>
                <span>涉及终端</span>
              </div>
              <div class="mal-stat">
                <b>{{ malwareFileStats.high }}</b>
                <span>高危及以上</span>
              </div>
              <p class="hint sm">含 FIM、文件模块、路径/哈希可识别的规则命中（不仅「文件落地」分类卡片）</p>
            </div>
            <div v-else class="focus-block">
              <div class="focus-title">重点关注事件</div>
              <div class="focus-grid">
                <button
                  v-for="c in focusCats"
                  :key="c.key"
                  type="button"
                  class="focus-card"
                  :class="{ on: focusKey === c.key }"
                  @click="toggleFocusCat(c.key)"
                >
                  <span class="focus-ico" :style="{ background: c.color }">{{ c.short }}</span>
                  <div>
                    <b>{{ c.label }}</b>
                    <em>{{ c.count }} 条 · {{ c.hosts }} 台主机</em>
                  </div>
                </button>
              </div>
            </div>

            <div class="split" :class="{ 'has-detail': !!listFocusEvent }">
              <aside class="term-pane" v-show="!listFocusEvent">
                <div class="term-hd"><b>威胁终端 ({{ eventAgents.length }})</b></div>
                <button type="button" class="term-all" :class="{ on: !eventAgentId }" @click="eventAgentId = ''">全部设备</button>
                <button
                  v-for="a in eventAgents"
                  :key="a.agent_id"
                  type="button"
                  class="term-row"
                  :class="{ on: eventAgentId === a.agent_id }"
                  @click="eventAgentId = a.agent_id"
                >
                  <i :class="['dot', a.online ? 'on' : '']" />
                  <span>{{ a.hostname || short(a.agent_id) }}</span>
                </button>
              </aside>

              <div class="panel table-pane">
                <div class="panel-hd">
                  <h3>{{ page === 'malware' ? '恶意文件告警' : '事件列表' }} ({{ filteredEvents.length }})</h3>
                </div>
                <div class="table-scroll">
                  <table class="evt-table">
                    <thead>
                      <tr>
                        <th class="chk">
                          <input type="checkbox" :checked="allEventsSelected" @change="toggleSelectAllEvents" />
                        </th>
                        <th>事件名称</th>
                        <th v-if="page !== 'malware' && !listFocusEvent" class="mono">执行命令（摘要）</th>
                        <th v-if="page === 'malware' && !listFocusEvent">文件路径 / 样本</th>
                        <th class="sortable" @click="toggleEventSort('severity')">
                          严重级别 <i class="sort-ico">{{ sortMark('severity') }}</i>
                        </th>
                        <th v-if="!listFocusEvent && page !== 'malware'">判定结果</th>
                        <th>影响终端</th>
                        <th
                          v-if="!listFocusEvent"
                          class="sortable"
                          @click="toggleEventSort('hit_count')"
                        >
                          告警日志数 <i class="sort-ico">{{ sortMark('hit_count') }}</i>
                        </th>
                        <th class="sortable" @click="toggleEventSort('updated_at')">
                          上次活跃 <i class="sort-ico">{{ sortMark('updated_at') }}</i>
                        </th>
                        <th v-if="!listFocusEvent" class="sortable" @click="toggleEventSort('created_at')">
                          首次发现 <i class="sort-ico">{{ sortMark('created_at') }}</i>
                        </th>
                        <th>操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr
                        v-for="e in pagedEvents"
                        :key="e.id"
                        class="row-click"
                        :class="{ on: listFocusId === e.id }"
                        @click="selectListEvent(e)"
                      >
                        <td class="chk" @click.stop>
                          <input type="checkbox" :checked="selectedEventIds.includes(e.id)" @change="toggleEventSelect(e.id)" />
                        </td>
                        <td class="strong">{{ e.title }}</td>
                        <td v-if="page !== 'malware' && !listFocusEvent" class="mono muted cmd-col" :title="eventCmdSummary(e)">{{ eventCmdSummary(e) || '—' }}</td>
                        <td v-if="page === 'malware' && !listFocusEvent" class="mono muted" :title="eventFileHint(e)">{{ shortPath(eventFileHint(e)) }}</td>
                        <td><span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span></td>
                        <td v-if="!listFocusEvent && page !== 'malware'"><span class="tag judge">{{ judgeOf(e) }}</span></td>
                        <td>{{ e.hostname || short(e.agent_id) }}</td>
                        <td v-if="!listFocusEvent" @click.stop>
                          <button
                            type="button"
                            class="log-n"
                            :class="{ hot: eventLogCount(e) > 1, multi: eventLogCount(e) >= 5 }"
                            :title="eventLogCount(e) > 1 ? `累计命中 ${eventLogCount(e)} 次 · 点击查看相关日志` : '首次命中 · 点击查看相关日志'"
                            @click="openEventLogHits(e)"
                          >{{ eventLogCount(e) }}</button>
                        </td>
                        <td>{{ fmtTime(e.updated_at || e.created_at) }}</td>
                        <td v-if="!listFocusEvent">{{ fmtTime(e.created_at) }}</td>
                        <td class="ops" @click.stop>
                          <div class="op-group">
                            <button type="button" class="op-ico primary" title="威胁视图" @click="openEvent(e)">视</button>
                            <button type="button" class="op-ico" title="加白" @click="openAllow(e)">白</button>
                            <button type="button" class="op-ico" title="删除" @click="removeEvent(e)">删</button>
                          </div>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                  <div v-if="!filteredEvents.length" class="empty ov-empty">
                    <p>{{ page === 'malware' ? '暂无文件类威胁告警' : (eventFiltersActive ? '当前筛选下无威胁事件' : '暂无威胁事件') }}</p>
                    <div class="row" style="justify-content:center;gap:8px;flex-wrap:wrap">
                      <button v-if="eventFiltersActive" type="button" class="btn sm" @click="resetEventFilters">清除筛选</button>
                      <button type="button" class="btn sm" @click="loadEvents(true, true)">重新同步</button>
                    </div>
                  </div>
                </div>
                <div v-if="filteredEvents.length" class="list-pager">
                  <span class="pg-info">第 {{ evtPage }} / {{ evtPageCount }} 页 · 共 {{ filteredEvents.length }} 条</span>
                  <div class="pg-acts">
                    <select v-model.number="evtPageSize" class="pg-size" @change="evtPage = 1">
                      <option :value="10">10 条/页</option>
                      <option :value="20">20 条/页</option>
                      <option :value="50">50 条/页</option>
                    </select>
                    <button type="button" class="btn sm" :disabled="evtPage <= 1" @click="evtPage--">上一页</button>
                    <button type="button" class="btn sm" :disabled="evtPage >= evtPageCount" @click="evtPage++">下一页</button>
                  </div>
                </div>
              </div>

              <aside v-if="listFocusEvent" class="panel ed-side">
                <div class="ed-top">
                  <div class="ed-top-l">
                    <b>威胁事件概览</b>
                    <div class="ed-nav">
                      <button type="button" class="btn-text" :disabled="!listFocusHasPrev" @click="navListFocus(-1)">上一条</button>
                      <button type="button" class="btn-text" :disabled="!listFocusHasNext" @click="navListFocus(1)">下一条</button>
                      <button type="button" class="ed-x" title="关闭" @click="clearListFocus">×</button>
                    </div>
                  </div>
                  <div class="ed-hero">
                    <span class="ed-shield">!</span>
                    <div class="ed-hero-main">
                      <h2 :title="listFocusEvent.title">{{ listFocusEvent.title }}</h2>
                      <div class="ed-hero-meta">
                        <span class="sev" :data-s="listFocusEvent.severity">{{ sevLabel(listFocusEvent.severity) }}</span>
                        <span class="ed-st" :data-s="listFocusEvent.status">{{ statusLabel(listFocusEvent.status) }}</span>
                        <span class="muted">{{ judgeOf(listFocusEvent) }}</span>
                      </div>
                      <button type="button" class="btn primary ed-open" @click="openEvent(listFocusEvent)">打开威胁视图</button>
                    </div>
                  </div>
                </div>

                <div class="ed-scroll">
                  <section class="ed-card" :class="{ folded: edFold.overview }">
                    <header class="ed-card-hd" @click="edFold.overview = !edFold.overview">
                      <b>威胁事件概览</b>
                      <i>{{ edFold.overview ? '+' : '−' }}</i>
                    </header>
                    <div v-show="!edFold.overview" class="ed-card-bd">
                      <dl class="ed-dl">
                        <div v-for="r in listOverviewCore" :key="'oc-' + r.k">
                          <dt>{{ r.k }}</dt>
                          <dd :class="{ mono: r.mono, 'ed-root': r.root }" :title="r.v">{{ r.v }}</dd>
                        </div>
                      </dl>
                      <template v-if="listOverviewExtra.length">
                        <button type="button" class="ed-more" @click.stop="edMore = !edMore">
                          {{ edMore ? '收起额外字段' : `查看更多（${listOverviewExtra.length}）` }} ▾
                        </button>
                        <dl v-if="edMore" class="ed-dl ed-dl-extra">
                          <div v-for="r in listOverviewExtra" :key="'oe-' + r.k">
                            <dt>{{ r.k }}</dt>
                            <dd :class="{ mono: r.mono }" :title="r.v">{{ r.v }}</dd>
                          </div>
                        </dl>
                      </template>
                    </div>
                  </section>

                  <section class="ed-card" :class="{ folded: edFold.host }">
                    <header class="ed-card-hd" @click="edFold.host = !edFold.host">
                      <b>影响终端 / 用户</b>
                      <i>{{ edFold.host ? '+' : '−' }}</i>
                    </header>
                    <div v-show="!edFold.host" class="ed-card-bd">
                      <div class="ed-host-grid">
                        <div class="ed-host-cell">
                          <span class="ed-k">终端</span>
                          <div class="ed-host-name">
                            <i :class="['dot', listFocusAgent?.online ? 'on' : '']" />
                            <b>{{ listFocusEvent.hostname || listFocusAgent?.hostname || short(listFocusEvent.agent_id) }}</b>
                            <em :class="listFocusAgent?.online ? 'on' : 'off'">{{ listFocusAgent?.online ? '在线' : '离线' }}</em>
                          </div>
                          <div class="ed-host-sub">
                            <span>IP {{ listFocusAgent?.ip || agentIp(listFocusEvent.agent_id) || '—' }}</span>
                            <span v-if="listFocusMac">MAC {{ listFocusMac }}</span>
                          </div>
                        </div>
                        <div class="ed-host-cell">
                          <span class="ed-k">用户</span>
                          <div class="ed-user">
                            <b>{{ listFocusUser || '未知用户' }}</b>
                            <small v-if="listFocusUserDomain">{{ listFocusUserDomain }}</small>
                            <small v-else-if="listFocusGroupLabel && listFocusGroupLabel !== '—'">分组 {{ listFocusGroupLabel }}</small>
                          </div>
                        </div>
                      </div>
                      <div class="ed-kv">
                        <div><span>操作系统</span><b>{{ listFocusOsLabel }}</b></div>
                        <div><span>职场 / 分组</span><b>{{ listFocusGroupLabel }}</b></div>
                        <div><span>最近登录</span><b>{{ listFocusUser || '—' }}</b></div>
                        <div><span>Agent</span><b class="mono">{{ short(listFocusEvent.agent_id) }}</b></div>
                      </div>
                    </div>
                  </section>

                  <section class="ed-card" :class="{ folded: edFold.alert }">
                    <header class="ed-card-hd" @click="edFold.alert = !edFold.alert">
                      <b>关键告警</b>
                      <i>{{ edFold.alert ? '+' : '−' }}</i>
                    </header>
                    <div v-show="!edFold.alert" class="ed-card-bd">
                      <div class="ed-tabs">
                        <button type="button" :class="{ on: edAlertTab === 'behavior' }" @click="edAlertTab = 'behavior'">
                          告警行为 ({{ listAlertBehaviors.length }})
                        </button>
                        <button type="button" :class="{ on: edAlertTab === 'file' }" @click="edAlertTab = 'file'">
                          恶意文件 ({{ listMaliciousFiles.length }})
                        </button>
                      </div>
                      <p class="hint sm ed-prev-hint">第 1 条为当前告警；其余仅当同终端、±2h 内且<strong>同规则 ID / 同路径 / 同 PID / 同标题对象（如 · 后文件名）/ 同注册表键</strong> 时才出现</p>
                      <div v-if="edAlertTab === 'behavior'" class="ed-beh">
                        <article v-for="b in listAlertBehaviors" :key="'beh-' + (b.eventId ?? b.title)" class="ed-beh-row" :class="{ current: b.isCurrent }">
                          <span class="sev" :data-s="b.severity">{{ sevLabel(b.severity) }}</span>
                          <div class="ed-beh-main">
                            <b :title="b.title">{{ b.title }}<i v-if="b.isCurrent" class="ed-cur-tag">当前</i></b>
                            <small>{{ b.sub }}</small>
                            <em>{{ b.time }}</em>
                          </div>
                        </article>
                        <p v-if="!listAlertBehaviors.length" class="empty sm">暂无关联告警行为</p>
                        <p v-else-if="listAlertBehaviors.length === 1" class="hint sm">仅展示当前告警；同终端 ±2h 内未找到规则/路径/标题强相关的其它事件</p>
                      </div>
                      <div v-else class="ed-beh">
                        <article v-for="(f, i) in listMaliciousFiles" :key="'mf-' + i" class="ed-beh-row">
                          <span class="ed-file-ico">文</span>
                          <div class="ed-beh-main">
                            <b class="mono" :title="f.name">{{ f.name }}</b>
                            <small class="mono" :title="f.path">{{ f.path }}</small>
                            <small v-if="f.extra" class="mono">{{ f.extra }}</small>
                            <em v-if="f.sourceTitle" class="ed-file-src">来自：{{ f.sourceTitle }}</em>
                          </div>
                        </article>
                        <p v-if="!listMaliciousFiles.length" class="empty sm">当前关联告警中无路径/样本（如纯注册表、网络类）— 请查看「告警行为」</p>
                        <p v-else-if="listAlertBehaviors.length > listMaliciousFiles.length" class="hint sm">注册表、父链缺失等告警不会出现在此列表；每条文件均标注来源告警。</p>
                      </div>
                    </div>
                  </section>

                  <section class="ed-card" :class="{ folded: edFold.judge }">
                    <header class="ed-card-hd" @click="edFold.judge = !edFold.judge">
                      <b>威胁研判</b>
                      <i>{{ edFold.judge ? '+' : '−' }}</i>
                    </header>
                    <div v-show="!edFold.judge" class="ed-card-bd">
                      <div class="ed-kv">
                        <div><span>判定结果</span><b>{{ judgeOf(listFocusEvent) }}</b></div>
                        <div><span>处置状态</span><b>{{ statusLabel(listFocusEvent.status) }}</b></div>
                        <div>
                          <span>严重级别</span>
                          <b><span class="sev" :data-s="listFocusEvent.severity">{{ sevLabel(listFocusEvent.severity) }}</span></b>
                        </div>
                        <div><span>检测模块</span><b>{{ modLabel(listFocusEvent.module) || '—' }}</b></div>
                        <div><span>事件类型</span><b class="mono">{{ listEvidenceFlat.etype || listEventEvidence.etype || listInferredEtype || '—' }}</b></div>
                        <div><span>规则 ID</span><b class="mono">{{ listEventEvidence.rule_id || listEvidenceFlat.watch || '—' }}</b></div>
                        <div class="span2"><span>匹配特征</span><b class="mono">{{ listEventEvidence.matched || '—' }}</b></div>
                        <div class="span2"><span>首次 / 活跃</span><b>{{ fmtTime(listFocusEvent.created_at) }} · {{ fmtTime(listFocusEvent.updated_at || listFocusEvent.created_at) }}</b></div>
                      </div>
                      <div class="ed-acts">
                        <button type="button" class="btn sm primary" @click="openEvent(listFocusEvent)">打开威胁视图</button>
                        <button type="button" class="btn sm" @click="openAllow(listFocusEvent)">加白</button>
                        <button type="button" class="btn sm" @click="openTimelineFor(listFocusEvent.agent_id)">时间线</button>
                      </div>
                    </div>
                  </section>
                </div>
              </aside>
            </div>
          </div>
        </div>
      </section>

      <!-- ========== 威胁详情（威胁图 + 右侧视图） ========== -->
      <section v-else-if="page === 'threat-view' && activeEvent" class="page threat-detail">
        <div class="tv-crumb">
          <button type="button" class="btn-text" @click="closeThreat">威胁事件</button>
          <span>/</span>
          <em>威胁事件详情：#{{ activeEvent.id }}</em>
        </div>

        <header class="tv-head">
          <div class="tv-head-main">
            <span class="tv-warn">⚠</span>
            <div>
              <h1>{{ activeEvent.title }}</h1>
              <div class="tv-meta">
                <span class="sev" :data-s="activeEvent.severity">{{ sevLabel(activeEvent.severity) }}</span>
                <span>发现 {{ fmtTime(activeEvent.created_at) }}</span>
                <span>活跃 {{ fmtTime(activeEvent.updated_at || activeEvent.created_at) }}</span>
                <span>{{ activeEvent.hostname || short(activeEvent.agent_id) }} · {{ agentIp(activeEvent.agent_id) }}</span>
              </div>
            </div>
          </div>
          <div class="tv-head-actions">
            <div class="tv-act-group">
              <span class="tv-act-label">处置</span>
              <button type="button" class="btn danger" :disabled="respBusy" @click="doResponse('kill_process')">结束进程</button>
              <button type="button" class="btn danger-outline" :disabled="respBusy" @click="doResponse('quarantine_file')">隔离文件</button>
              <button type="button" class="btn danger-outline" :disabled="respBusy" @click="doResponse('isolate_network')">网络隔离</button>
              <button type="button" class="btn" :disabled="respBusy" @click="doResponse('unisolate_network')">解除隔离</button>
              <button type="button" class="btn" :disabled="respBusy" @click="doResponse('scan_memory')">内存扫描</button>
            </div>
            <div class="tv-act-group nav">
              <button type="button" class="btn" @click="threatTab = 'response'; loadRespCommands()">处置结果</button>
              <button type="button" class="btn" @click="openTimelineFor(activeEvent.agent_id)">时间线</button>
              <button type="button" class="btn" @click="jumpToHost">终端资产</button>
              <button type="button" class="btn" @click="openAllow(activeEvent)">加白</button>
              <button type="button" class="btn" @click="closeThreat">返回列表</button>
            </div>
          </div>
        </header>

        <div class="tv-tabs">
          <button type="button" class="tv-tab" :class="{ on: threatTab === 'graph' }" @click="threatTab = 'graph'">威胁视图</button>
          <button type="button" class="tv-tab" :class="{ on: threatTab === 'story' }" @click="threatTab = 'story'; loadAttackStory()">攻击故事</button>
          <button type="button" class="tv-tab" :class="{ on: threatTab === 'evidence' }" @click="threatTab = 'evidence'">证据详情</button>
          <button type="button" class="tv-tab" :class="{ on: threatTab === 'response' }" @click="threatTab = 'response'; loadRespCommands()">
            处置结果
            <em v-if="respPendingCount" class="tab-n">{{ respPendingCount }}</em>
          </button>
        </div>

        <div class="tv-body">
          <div class="tv-canvas graph" v-show="threatTab === 'graph'">
            <div class="tv-graph-banner">
              <div class="tv-graph-banner-l">
                <span class="sev lg" :data-s="activeEvent.severity">{{ sevLabel(activeEvent.severity) }}</span>
                <span class="tv-graph-banner-t">攻击链概览</span>
                <span class="muted">{{ judgeOf(activeEvent) }}</span>
              </div>
              <div class="tv-canvas-tools">
                <span class="chip soft">逻辑关系</span>
                <span class="chip soft">{{ modLabel(activeEvent.module) || '检测模块' }}</span>
                <span v-if="eventAttck.technique" class="chip soft atk">{{ eventAttck.technique }}</span>
              </div>
            </div>
            <div class="tv-tree-bar">
              <label class="tv-tree-opt"><input type="checkbox" v-model="tvShowDotted" /> 展示虚线关联关系</label>
              <label class="tv-tree-opt"><input type="checkbox" v-model="tvReadable" /> 增强可读性</label>
              <button type="button" class="btn sm" :disabled="threatTreeBusy" @click="loadThreatProcessTree">刷新进程树</button>
            </div>
            <div v-if="threatDropChainSteps.length >= 2" class="tv-drop-chain">
              <div class="tv-drop-head">
                <span class="tv-drop-title">释放 / 投递链</span>
                <span class="muted">父进程 → 写文件 → 子进程（告警前后时间窗口）</span>
              </div>
              <div class="tv-drop-row">
                <template v-for="(s, i) in threatDropChainSteps" :key="s.id || i">
                  <div v-if="i > 0" class="tv-drop-edge">
                    <em>{{ threatDropEdgeLabel(i) }}</em>
                    <span class="line" />
                  </div>
                  <div
                    class="tv-drop-node"
                    :class="[s.kind, s.role, { hit: s.is_hit }]"
                    @click="s.is_hit && (threatPanelNode = 'hit')"
                  >
                    <span class="tv-drop-kind">{{ threatDropKindLabel(s) }}</span>
                    <b :title="s.path || s.name">{{ s.name }}</b>
                    <small v-if="s.kind === 'proc' && s.pid">PID {{ s.pid }}</small>
                    <small v-else-if="s.path" :title="s.path">{{ shortPath(s.path) }}</small>
                  </div>
                </template>
              </div>
            </div>
            <div class="tv-graph-wrap">
              <div class="tv-graph-stage" :style="{ transform: `scale(${tvZoom})` }">
                <p v-if="threatTreeBusy" class="empty sm">进程树加载中…</p>
                <template v-else-if="threatGraphLayout.layers.length">
                  <div class="tv-graph-host">
                    <span class="tv-proc-ico host">🖥</span>
                    <div>
                      <b>{{ activeEvent.hostname || short(activeEvent.agent_id) }}</b>
                      <small>{{ agentIp(activeEvent.agent_id) }} · {{ judgeOf(activeEvent) }}</small>
                    </div>
                  </div>
                  <div
                    class="tv-graph-scroll"
                    :style="{ width: threatGraphLayout.width + 'px', height: threatGraphLayout.height + 'px' }"
                  >
                    <svg
                      class="tv-graph-svg"
                      :class="{ dotted: tvShowDotted }"
                      :width="threatGraphLayout.width"
                      :height="threatGraphLayout.height"
                      aria-hidden="true"
                    >
                      <defs>
                        <marker
                          id="tv-graph-arrow"
                          markerWidth="8"
                          markerHeight="8"
                          refX="7"
                          refY="4"
                          orient="auto"
                          markerUnits="strokeWidth"
                        >
                          <path d="M0,0 L8,4 L0,8 z" fill="context-stroke" />
                        </marker>
                      </defs>
                      <path
                        v-for="(p, i) in threatGraphLayout.paths"
                        :key="'tg-' + i"
                        class="tv-graph-edge"
                        :class="{ repaired: p.repaired, hot: p.hot }"
                        :d="p.d"
                        fill="none"
                        :stroke="p.repaired ? '#f97316' : (p.hot ? '#f87171' : '#64748b')"
                        stroke-width="2.5"
                        stroke-linecap="round"
                        :stroke-dasharray="(tvShowDotted || p.repaired) ? '7 5' : '0'"
                        marker-end="url(#tv-graph-arrow)"
                      />
                    </svg>
                    <div class="tv-graph-cols">
                      <div
                        v-for="(col, ci) in threatGraphLayout.layers"
                        :key="'col-' + ci"
                        class="tv-graph-col"
                        :style="{ width: threatGraphLayout.colW + 'px', minHeight: threatGraphLayout.height + 'px' }"
                      >
                        <div
                          v-for="n in col"
                          :key="n.id"
                          class="tv-proc-node"
                          :class="{
                            hit: n.is_hit,
                            on: n.is_hit && threatPanelNode === 'hit',
                            readable: tvReadable,
                            missing: n.synthetic || n.missing,
                          }"
                          :style="threatNodeStyle(n.id)"
                          @click="onThreatGraphNode(n)"
                        >
                          <button
                            v-if="threatTreeHasKids(n.id)"
                            type="button"
                            class="tv-proc-fold"
                            @click.stop="toggleThreatTreeNode(n.id)"
                          >{{ tvTreeExpanded[n.id] === false ? '+' : '−' }}</button>
                          <span class="tv-proc-ico">⚙</span>
                          <b :title="n.name">{{ n.name }}</b>
                          <small>PID {{ n.pid }}<template v-if="n.exit_time"> · 已退出</template></small>
                          <small
                            v-if="n.command_line"
                            class="tv-proc-cmd mono"
                            :class="{ hit: n.is_hit }"
                            :title="n.command_line"
                          >{{ n.command_line }}</small>
                          <small v-else-if="n.path" class="tv-proc-cmd mono" :title="n.path">{{ n.path }}</small>
                          <em v-if="n.is_hit" class="tv-hit-tag">威胁命中</em>
                        </div>
                      </div>
                    </div>
                  </div>
                </template>
                <div v-else class="tv-flow-stage">
                  <div class="tv-flow">
                    <template v-for="(n, i) in graphNodes" :key="n.key">
                      <div v-if="i > 0" class="tvf-edge" :class="{ hot: n.tone === 'hit' }">
                        <em>{{ n.edge }}</em>
                        <span class="line" />
                      </div>
                      <div
                        class="tvf-node"
                        :class="[n.tone, { on: n.tone === 'hit' && threatPanelNode === 'hit' }]"
                        @click="n.tone === 'hit' && (threatPanelNode = 'hit')"
                      >
                        <span class="tvf-kind">{{ n.kind }}</span>
                        <b :title="n.title">{{ n.title }}</b>
                        <small v-if="n.sub" :title="n.sub">{{ n.sub }}</small>
                        <div v-if="n.meta && n.meta.length" class="tvf-meta">
                          <span v-for="m in n.meta" :key="m.k" :class="m.cls"><i>{{ m.k }}</i>{{ m.v }}</span>
                        </div>
                      </div>
                    </template>
                  </div>
                </div>
              </div>
              <aside class="tv-graph-tools">
                <button type="button" title="放大" @click="tvZoom = Math.min(1.45, +(tvZoom + 0.1).toFixed(2))">+</button>
                <button type="button" title="缩小" @click="tvZoom = Math.max(0.55, +(tvZoom - 0.1).toFixed(2))">−</button>
                <button type="button" title="重置视图" @click="tvZoom = 1">⟲</button>
              </aside>
            </div>
            <div class="tv-graph-foot">
              <div class="tvf-rule">
                <div class="tvf-rule-item span4">
                  <label>规则名称</label>
                  <b>{{ displayRuleTitle(activeEvent) }}</b>
                </div>
                <div class="tvf-rule-item span2">
                  <label>规则 ID</label>
                  <b class="mono">{{ eventEvidence.rule_id || '—' }}</b>
                </div>
                <div class="tvf-rule-item span3">
                  <label>规则来源</label>
                  <b>{{ ruleSourceLabel }}</b>
                </div>
                <div class="tvf-rule-item span3">
                  <label>判定结果</label>
                  <b class="judge">{{ judgeOf(activeEvent) }}</b>
                </div>
                <div class="tvf-rule-item wide">
                  <label>匹配特征</label>
                  <b class="mono">{{ eventEvidence.matched || evidencePath || '—' }}</b>
                </div>
                <div class="tvf-rule-item span4">
                  <label>影响终端</label>
                  <b>{{ activeEvent.hostname || short(activeEvent.agent_id) }} · {{ agentIp(activeEvent.agent_id) }}</b>
                </div>
                <div class="tvf-rule-item span4">
                  <label>ATT&CK</label>
                  <b>{{ eventAttck.technique ? techChip(eventAttck.technique, eventAttck.label) : '—' }}</b>
                </div>
                <div class="tvf-rule-item span4">
                  <label>检测模块</label>
                  <b>{{ modLabel(activeEvent.module) || '—' }}</b>
                </div>
              </div>
              <p class="tv-canvas-hint">横向进程树：点击「威胁命中」节点 · 右侧查看对象详情与处置；± 折叠子进程</p>
            </div>
          </div>

          <div class="tv-canvas story-pane" v-show="threatTab === 'story'">
            <div class="panel-hd bare">
              <h3>攻击故事链</h3>
              <button type="button" class="btn sm" @click="loadAttackStory">刷新</button>
            </div>
            <div v-if="storyTech.length" class="story-techs">
              <span v-for="t in storyTech" :key="t.id" class="stech" :title="t.tactic || ''">{{ techChip(t.id, t.label) }}</span>
            </div>
            <div v-if="storyNodes.length" class="story-chain">
              <article v-for="(n, i) in storyNodes" :key="i" class="story-node" :data-k="n.kind">
                <div class="sn-axis">
                  <i class="dot" /><span class="line" v-if="i < storyNodes.length - 1" />
                </div>
                <div class="sn-body">
                  <div class="sn-top">
                    <span class="sn-kind" :data-k="n.kind">{{ n.kind === 'threat' ? '威胁' : '时间线' }}</span>
                    <span v-if="n.technique" class="stech compact" :title="n.tactic || ''">{{ techChip(n.technique, n.technique_label) }}</span>
                    <span v-if="n.severity && n.severity !== 'info'" class="sev" :data-s="n.severity">{{ sevLabel(n.severity) }}</span>
                    <time>{{ fmtTime(n.ts) }}</time>
                  </div>
                  <h4 class="sn-title">{{ n.title }}</h4>
                  <div v-if="storyDetailPreview(n).length" class="sn-meta">
                    <span v-for="p in storyDetailPreview(n)" :key="p.k"><em>{{ p.k }}</em>{{ p.v }}</span>
                  </div>
                </div>
              </article>
            </div>
            <p v-else class="empty">暂无故事节点；主机有时间线或威胁事件后将自动串联。</p>
            <div v-if="relatedPayload?.edges?.length || relatedPayload?.items?.length" class="panel pad" style="margin-top:12px">
              <h4>载荷关联边</h4>
              <p v-if="relatedPayload.payload_key" class="mono sm muted">key {{ relatedPayload.payload_key }}</p>
              <div v-if="relatedPayload.edges?.length" class="sn-meta" style="margin:6px 0">
                <span v-for="(e, i) in relatedPayload.edges" :key="i"><em>{{ e.kind }}</em>{{ e.value }}</span>
              </div>
              <ul v-if="relatedPayload.items?.length" class="hsp-advise">
                <li v-for="it in relatedPayload.items" :key="it.id">
                  <button type="button" class="btn-text" @click="openEventById(it.id)">#{{ it.id }} {{ it.title }}</button>
                  <span class="muted sm"> · {{ it.module }} · {{ sevLabel(it.severity) }}</span>
                </li>
              </ul>
            </div>
          </div>

          <div class="tv-canvas plain" v-show="threatTab === 'evidence'">
            <div class="ev-hero">
              <div>
                <span class="sev" :data-s="activeEvent.severity">{{ sevLabel(activeEvent.severity) }}</span>
                <b>{{ activeEvent.title }}</b>
                <p>{{ alertDesc || '结合进程链、路径与签名综合研判。' }}</p>
              </div>
              <div class="ev-hero-tags">
                <span class="chip soft">{{ modLabel(activeEvent.module) || '模块' }}</span>
                <span class="chip soft">{{ ruleSourceLabel }}</span>
                <span v-if="eventAttck.technique" class="stech compact" :title="eventAttck.tactic">{{ techChip(eventAttck.technique, eventAttck.label) }}</span>
              </div>
            </div>
            <div class="ev-groups">
              <section v-for="g in evidenceGroupsFull" :key="g.title" class="ev-group">
                <h4><i :data-t="g.tone" />{{ g.title }}<em>{{ g.items.length }}</em></h4>
                <div class="ev-cards">
                  <div v-for="it in g.items" :key="it.k" class="ev-card" :class="{ wide: it.wide, mono: it.mono }">
                    <label>{{ it.label }}</label>
                    <div class="ev-val" :title="it.v">
                      <span v-if="it.badge" class="ev-badge" :data-t="it.badge">{{ it.v }}</span>
                      <template v-else>{{ it.v }}</template>
                    </div>
                    <button v-if="it.wide || it.copy" type="button" class="ev-copy" @click="copyText(it.v)">复制</button>
                  </div>
                </div>
              </section>
            </div>
            <details class="ev-raw">
              <summary>原始证据 JSON</summary>
              <pre class="raw-detail">{{ evidenceRawText }}</pre>
            </details>
          </div>

          <div class="tv-canvas" v-show="threatTab === 'response'">
            <div class="panel-hd bare">
              <h3>本机处置指令</h3>
              <button type="button" class="btn sm" @click="loadRespCommands">刷新状态</button>
            </div>
            <p class="hint" style="margin:0 0 12px">下发后由 Agent 下一心跳执行；状态：pending→sent→done/failed</p>
            <table v-if="respCommands.length">
              <thead>
                <tr><th>时间</th><th>动作</th><th>状态</th><th>参数</th><th>结果</th><th></th></tr>
              </thead>
              <tbody>
                <tr v-for="c in respCommands" :key="c.id">
                  <td>{{ fmtTime(c.updated_at || c.created_at) }}</td>
                  <td>{{ actionLabel(c.action) }}</td>
                  <td><span class="cmd-st" :data-s="c.status">{{ cmdStatusLabel(c.status) }}</span></td>
                  <td class="muted mono">{{ shortJson(c.params_json) }}</td>
                  <td class="muted" :title="c.result_json">
                    <template v-if="c.action === 'scan_memory' && c.status === 'done'">
                      扫描 {{ parseJsonSafe(c.result_json).scanned ?? 0 }} 个进程，发现 {{ parseJsonSafe(c.result_json).finding_count ?? 0 }} 处
                    </template>
                    <template v-else>{{ shortJson(c.result_json) }}</template>
                  </td>
                  <td>
                    <button
                      v-if="c.action === 'quarantine_file' && c.status === 'done'"
                      type="button"
                      class="btn-text"
                      @click="restoreQuarantined(c)"
                    >回滚</button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p v-else class="empty">暂无处置指令。点击上方红色按钮下发后，在此查看是否成功。</p>
            <button type="button" class="btn" style="margin-top:12px" @click="goAuditPage">打开处置审计 →</button>
          </div>

          <aside class="tv-side">
            <div class="tvs-hd">
              <span class="tvs-file">!</span>
              <div>
                <b>{{ evidenceDesc?.title || evidenceName || activeEvent.title }}</b>
                <small>威胁视图</small>
              </div>
            </div>

            <div class="tvs-sec tvs-cmd-block">
              <h4>执行命令 / 启动项</h4>
              <pre v-if="evidenceCommandLine || evidenceFlat.script_block" class="tvs-cmd-pre mono" :title="evidenceCommandLine || evidenceFlat.script_block">{{ evidenceCommandLine || evidenceFlat.script_block }}</pre>
              <p v-else-if="evidenceFlat.reg_key || evidenceFlat.key" class="hint sm tvs-cmd-hint">
                本条为注册表类告警，无独立进程命令行。写入值：<span class="mono">{{ evidenceFlat.value || '—' }}</span>
                <template v-if="evidenceFlat.image || evidenceFlat.process_path"> · 关联进程映像 {{ evidenceFlat.image || evidenceFlat.process_path }}</template>
              </p>
              <p v-else class="hint sm tvs-cmd-hint">
                暂无命令行。可点「刷新进程树」从进程实体/时间线补全，或查看「匹配特征」。
                <template v-if="threatHostAgent">
                  <br><span class="capture-hint">采集能力：{{ captureCaptureHint(threatHostAgent) }}</span>
                </template>
                <span v-if="!(evidenceFlat.chain && evidenceFlat.chain.length)" class="muted"> · 本条无 PTM 规则链</span>
              </p>
              <div v-if="!(evidenceCommandLine || evidenceFlat.script_block)" class="tvs-cmd-actions">
                <button type="button" class="btn-text sm" @click="jumpThreatTimelineWindow">同主机 ±5 分钟时间线</button>
                <button type="button" class="btn-text sm" @click="huntFromEmptyCmd">按 PID/进程名狩猎</button>
              </div>
            </div>

            <div v-if="evidenceChainRows.length" class="tvs-sec tvs-chain-block">
              <h4>规则链 / 时间序</h4>
              <table class="chain-tbl">
                <thead><tr><th>#</th><th>时间</th><th>类型</th><th>摘要</th><th>命令行</th></tr></thead>
                <tbody>
                  <tr v-for="(row, idx) in evidenceChainRows" :key="idx">
                    <td>{{ idx + 1 }}</td>
                    <td class="muted">{{ row.ts || '—' }}</td>
                    <td class="mono">{{ row.etype || '—' }}</td>
                    <td>{{ row.summary || '—' }}</td>
                    <td class="mono" :title="row.command_line">{{ row.command_line || '—' }}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div class="tvs-sec">
              <h4>对象信息</h4>
              <dl class="td-dl">
                <template v-if="evidenceDesc && evidenceDesc.rows.length">
                  <div v-for="r in evidenceDesc.rows" :key="r.k">
                    <dt>{{ r.k }}</dt><dd :class="{ mono: r.mono }" :title="r.v">{{ r.v }}</dd>
                  </div>
                </template>
                <template v-else-if="isRegistryEvidence">
                  <div><dt>监控点</dt><dd>{{ evidenceFlat.label || evidenceName || '—' }}</dd></div>
                  <div><dt>值名</dt><dd>{{ evidenceFlat.value_name || '—' }}</dd></div>
                  <div><dt>注册表键</dt><dd class="mono" :title="evidenceFlat.key || evidenceFlat.reg_key">{{ evidenceFlat.key || evidenceFlat.reg_key || '—' }}</dd></div>
                  <div><dt>写入值</dt><dd class="mono" :title="evidenceFlat.value">{{ evidenceFlat.value != null && evidenceFlat.value !== '' ? evidenceFlat.value : '—' }}</dd></div>
                  <div v-if="evidenceFlat.old_value"><dt>旧值</dt><dd class="mono">{{ evidenceFlat.old_value }}</dd></div>
                  <div><dt>Hive</dt><dd>{{ evidenceFlat.hive || '—' }}</dd></div>
                  <div><dt>变更</dt><dd>{{ evidenceFlat.change ? evValueText('change', evidenceFlat.change) : '—' }}</dd></div>
                </template>
                <template v-else>
                  <div><dt>名称</dt><dd>{{ evidenceName || '—' }}</dd></div>
                  <div><dt>路径</dt><dd class="mono" :title="evidencePath">{{ evidencePath || '—' }}</dd></div>
                  <div v-if="evidenceCommandLine" class="span2"><dt>命令行</dt><dd class="mono" :title="evidenceCommandLine">{{ evidenceCommandLine }}</dd></div>
                  <div v-if="evidenceFlat.parent_name || evidenceFlat.ppid"><dt>父进程</dt><dd>{{ evidenceFlat.parent_name || '—' }}{{ evidenceFlat.ppid ? `（PPID ${evidenceFlat.ppid}）` : '' }}</dd></div>
                  <div v-if="evidenceFlat.user"><dt>用户</dt><dd>{{ evidenceFlat.user }}</dd></div>
                  <div v-if="evidenceFlat.signed"><dt>签名</dt><dd>{{ evValueText('signed', evidenceFlat.signed) }}</dd></div>
                  <div v-if="evidenceFlat.sha256"><dt>SHA256</dt><dd class="mono" :title="evidenceFlat.sha256">{{ evidenceFlat.sha256 }}</dd></div>
                </template>
                <div><dt>模块</dt><dd>{{ modLabel(activeEvent.module) || '—' }}</dd></div>
                <div><dt>主机</dt><dd>{{ activeEvent.hostname || short(activeEvent.agent_id) }}</dd></div>
                <div><dt>IP</dt><dd>{{ agentIp(activeEvent.agent_id) }}</dd></div>
                <div><dt>Agent</dt><dd class="mono">{{ short(activeEvent.agent_id) }}</dd></div>
                <div><dt>首次发现</dt><dd>{{ fmtTime(activeEvent.created_at) }}</dd></div>
                <div><dt>最近活跃</dt><dd>{{ fmtTime(activeEvent.updated_at) }}</dd></div>
                <div><dt>状态</dt><dd>{{ statusLabel(activeEvent.status) }}</dd></div>
              </dl>
            </div>

            <div class="tvs-sec">
              <h4>威胁信息</h4>
              <div class="intel">
                <p class="intel-tip">{{ isRegistryEvidence ? '注册表安全项被修改，请核对是否为预期变更' : '该对象被判定为规则命中 / 可疑项' }}</p>
                <span class="virus-tag">{{ activeEvent.title }}</span>
                <dl class="td-dl compact">
                  <div><dt>严重级别</dt><dd><span class="sev" :data-s="activeEvent.severity">{{ sevLabel(activeEvent.severity) }}</span></dd></div>
                  <div><dt>规则 ID</dt><dd>{{ eventEvidence.rule_id || evidenceFlat.watch || '—' }}</dd></div>
                  <div><dt>规则来源</dt><dd>{{ ruleSourceLabel }}</dd></div>
                  <div><dt>匹配特征</dt><dd class="mono">{{ eventEvidence.matched || '—' }}</dd></div>
                  <div><dt>判定结果</dt><dd>{{ judgeOf(activeEvent) }}</dd></div>
                  <div v-if="eventAttck.technique"><dt>ATT&CK</dt><dd>{{ techChip(eventAttck.technique, eventAttck.label) }}</dd></div>
                  <div v-if="eventAttck.tactic"><dt>战术</dt><dd>{{ eventAttck.tacticLabel || eventAttck.tactic }}</dd></div>
                </dl>
              </div>
            </div>

            <div class="tvs-sec" v-if="isRegistryEvidence && !evidenceDesc">
              <h4>注册表详情</h4>
              <dl class="td-dl">
                <div><dt>事件类型</dt><dd>{{ evidenceFlat.etype || eventEvidence.etype || 'registry_set' }}</dd></div>
                <div><dt>类别</dt><dd>{{ evidenceFlat.category || '—' }}</dd></div>
                <div><dt>值类型</dt><dd>{{ evidenceFlat.value_type || '—' }}</dd></div>
                <div><dt>采集来源</dt><dd>{{ evidenceFlat.source || 'reg_notify' }}</dd></div>
                <div><dt>监控规则</dt><dd>{{ evidenceFlat.watch || '—' }}</dd></div>
                <div v-if="evidenceFlat.user_sid"><dt>用户 SID</dt><dd class="mono">{{ evidenceFlat.user_sid }}</dd></div>
                <div v-if="evidenceFlat.offline"><dt>离线变更</dt><dd>是</dd></div>
              </dl>
            </div>
            <div class="tvs-sec" v-else>
              <h4>进程 / 文件</h4>
              <dl class="td-dl">
                <div><dt>命令行</dt><dd>{{ evidenceFlat.command_line || evidenceFlat.command || '—' }}</dd></div>
                <div><dt>PID</dt><dd>{{ evidenceFlat.pid ?? '—' }}</dd></div>
                <div><dt>进程名</dt><dd>{{ evidenceFlat.process_name || evidenceFlat.name || evidenceFlat.host_process || '—' }}</dd></div>
                <div v-if="evidenceFlat.path || evidenceFlat.image"><dt>路径</dt><dd class="mono" :title="evidenceFlat.path || evidenceFlat.image">{{ evidenceFlat.path || evidenceFlat.image }}</dd></div>
                <div><dt>父进程</dt><dd>{{ evidenceFlat.parent_name || '—' }} <em v-if="evidenceFlat.ppid">({{ evidenceFlat.ppid }})</em></dd></div>
                <div><dt>用户</dt><dd>{{ evidenceFlat.user || '—' }}</dd></div>
                <div><dt>签名</dt><dd>{{ evidenceFlat.signed || '—' }}</dd></div>
                <div><dt>签名者</dt><dd>{{ evidenceFlat.signer || '—' }}</dd></div>
                <div><dt>公司</dt><dd>{{ evidenceFlat.company || '—' }}</dd></div>
                <div><dt>SHA256</dt><dd class="mono">{{ evidenceFlat.sha256 || '—' }}</dd></div>
                <div><dt>事件类型</dt><dd>{{ evidenceFlat.etype || eventEvidence.etype || '—' }}</dd></div>
                <div><dt>扩展名</dt><dd>{{ evidenceFlat.ext || '—' }}</dd></div>
                <div><dt>大小</dt><dd>{{ evidenceFlat.size_kb != null ? `${evidenceFlat.size_kb} KB` : (evidenceFlat.size ?? '—') }}</dd></div>
              </dl>
            </div>

            <div class="tvs-sec" v-if="sideExtraFields.length">
              <h4>更多字段</h4>
              <dl class="td-dl">
                <div v-for="it in sideExtraFields" :key="it.k">
                  <dt>{{ it.label }}</dt>
                  <dd :title="it.v">{{ it.v }}</dd>
                </div>
              </dl>
            </div>
          </aside>
        </div>
      </section>

      <!-- ========== 终端列表 ========== -->
      <section v-else-if="page === 'hosts' && !selected" class="page hosts-page">
        <header class="page-hd">
          <div>
            <h1>终端列表</h1>
            <p class="desc">接入主机一览；点主机查看进程 / 服务 / 网络等模块与可疑行为</p>
          </div>
          <div class="hd-right">
            <input v-model="q" class="search" placeholder="搜索主机 / IP…" />
            <button type="button" class="btn primary" @click="refresh">刷新</button>
          </div>
        </header>

        <div class="host-summary">
          <div class="hs"><span>全部</span><b>{{ agents.length }}</b></div>
          <div class="hs on"><span>在线</span><b>{{ onlineCount }}</b></div>
          <div class="hs off"><span>离线</span><b>{{ agents.length - onlineCount }}</b></div>
          <div class="hs danger"><span>有告警</span><b>{{ hostsWithAlert }}</b></div>
        </div>

        <div class="panel host-panel">
          <div class="host-table">
            <div class="ht-head">
              <span>主机</span><span>系统</span><span>IP</span><span>状态</span><span>最近心跳</span><span>版本</span><span>告警</span><span>操作</span>
            </div>
            <div
              v-for="a in filteredAgents"
              :key="a.agent_id"
              class="ht-row"
            >
              <span class="ht-host">
                <i :class="['dot', a.online ? 'on' : '']" />
                <b>{{ a.hostname || short(a.agent_id) }}</b>
              </span>
              <span>{{ a.os_family || '—' }}</span>
              <span class="mono">{{ a.ip || '—' }}</span>
              <span><em class="pill" :class="{ on: a.online }">{{ a.online ? '在线' : '离线' }}</em></span>
              <span class="muted">{{ fmtTime(a.last_seen) }}</span>
              <span>{{ a.version || '—' }}<em v-if="a.outdated" class="pill warn" title="落后于当前发布版本" style="margin-left:4px">可升级</em></span>
              <span>
                <em v-if="alertCount(a.agent_id)" class="alert-n">{{ alertCount(a.agent_id) }}</em>
                <em v-else class="muted">0</em>
              </span>
              <span class="ops">
                <button type="button" class="btn sm" @click="openHost(a, 'hosts')">查看主机</button>
                <button type="button" class="btn sm" :disabled="!a.online" @click="uninstallHost(a)">远程卸载</button>
                <button type="button" class="btn sm danger" @click="removeHost(a)">删除记录</button>
              </span>
            </div>
            <p v-if="!filteredAgents.length" class="empty">暂无终端，请先部署安装包</p>
          </div>
        </div>
      </section>

      <!-- ========== 主机详情（模块数据 + 可疑行为） ========== -->
      <section v-else-if="page === 'hosts' && selected" class="page host-detail">
        <header class="host-hdr">
          <div class="host-hdr-top">
            <div class="host-hdr-id">
              <button type="button" class="btn sm ghost host-back" @click="backFromHost">← 返回</button>
              <div class="host-hdr-title">
                <h1>{{ selected.hostname || selected.agent_id }}</h1>
                <p class="host-hdr-meta">
                  <i :class="['dot', selected.online ? 'on' : '']" />
                  <em class="pill" :class="{ on: selected.online }">{{ selected.online ? '在线' : '离线' }}</em>
                  <span>{{ selected.ip || '—' }}</span>
                  <span>心跳 {{ fmtTime(selected.last_seen) }}</span>
                  <span>Agent v{{ selected.version || '—' }}</span>
                  <em v-if="selected.revoked" class="pill warn">凭据已吊销</em>
                </p>
              </div>
            </div>
            <div class="host-hdr-acts">
              <span class="sync-pill" :class="{ on: selected.online }">
                <i class="sync-dot" />
                {{ selected.online ? '实时同步' : '离线' }}
              </span>
              <button type="button" class="btn" :disabled="diagBusy || !selected.online" @click="requestDiagnostics(selected)">
                {{ diagBusy ? '诊断中…' : '诊断包' }}
              </button>
              <button type="button" class="btn primary" @click="refreshHostDetail">刷新</button>
              <div class="host-more">
                <button type="button" class="btn" :class="{ on: hostHdrMore }" @click="hostHdrMore = !hostHdrMore">更多 ▾</button>
                <div v-if="hostHdrMore" class="host-more-menu" @click.stop>
                  <label class="host-more-tags">
                    <span>标签</span>
                    <input v-model="hostTagEdit" class="field" placeholder="逗号分隔" @focus="hostTagEdit = (tagMap[selected.agent_id] || []).join(',')" />
                    <button type="button" class="btn sm" @click="saveHostTags(selected); hostHdrMore = false">保存</button>
                  </label>
                  <button type="button" class="host-more-item" :disabled="!selected.online" @click="uninstallHost(selected); hostHdrMore = false">远程卸载</button>
                  <button v-if="isAdmin && selected.has_secret" type="button" class="host-more-item" @click="toggleRevoke(selected); hostHdrMore = false">
                    {{ selected.revoked ? '恢复凭据' : '吊销凭据' }}
                  </button>
                  <button type="button" class="host-more-item danger" @click="removeHost(selected); hostHdrMore = false">删除记录</button>
                </div>
              </div>
            </div>
          </div>

          <div class="host-hdr-stats">
            <span v-for="c in hostQuickStats(selected)" :key="c.k" class="hchip" :class="{ warn: c.warn }" :title="c.title || ''">{{ c.k }} {{ c.v }}</span>
            <span
              v-for="c in componentWarnChips(selected).slice(0, 3)"
              :key="'cw-' + c.k"
              class="hchip warn"
              :title="c.message || ''"
            >{{ c.k }} {{ c.state }}</span>
            <button
              v-if="hostSensorsPanel(selected)"
              type="button"
              class="host-health-toggle"
              :class="{ warn: (hostSensorsPanel(selected).advise?.length || 0) > 0 || hostSensorsPanel(selected).level === 'poor' }"
              @click="hostHealthOpen = !hostHealthOpen"
            >
              采集健康 {{ hostSensorsPanel(selected).score ?? '—' }}
              <em>{{ hostHealthOpen ? '▾' : '▸' }}</em>
            </button>
          </div>

          <div v-if="hostHealthOpen && hostSensorsPanel(selected)" class="host-health-card open">
            <div class="host-health-body">
              <div class="hsp-row">
                <span class="hsp-score" :data-lv="hostSensorsPanel(selected).level">{{ hostSensorsPanel(selected).score ?? '—' }}</span>
                <span class="hsp-chip">{{ hostSensorsPanel(selected).pipeline }}</span>
                <span v-if="hostSensorsPanel(selected).cmdFill != null" class="hsp-chip">cmd {{ hostSensorsPanel(selected).cmdFill }}%</span>
                <span v-if="hostSensorsPanel(selected).disks" class="hsp-chip" :class="{ warn: String(hostSensorsPanel(selected).disks).includes('100%') }">{{ hostSensorsPanel(selected).disks }}</span>
                <span v-if="hostSensorsPanel(selected).netLine" class="hsp-chip">{{ hostSensorsPanel(selected).netLine }}</span>
              </div>
              <div v-if="hostSensorsPanel(selected).statusChips?.length" class="hsp-row hsp-chips">
                <span
                  v-for="(c, i) in hostSensorsPanel(selected).statusChips"
                  :key="i"
                  class="hsp-chip"
                  :class="{ warn: c.warn, ok: c.ok }"
                  :title="c.title || ''"
                >{{ c.label }}</span>
              </div>
              <div v-if="componentHealthChips(selected).length" class="hsp-row hsp-chips">
                <span class="hsp-label">组件</span>
                <span
                  v-for="c in componentHealthChips(selected)"
                  :key="'cmp-' + c.k"
                  class="hsp-chip"
                  :class="{ warn: c.state === 'DEGRADED', off: c.state === 'OFF', ok: c.state === 'OK' }"
                  :title="c.message || ''"
                >{{ c.k }} {{ c.state }}</span>
              </div>
              <div v-if="hostSensorsPanel(selected).channelChips?.length" class="hsp-row hsp-channels">
                <span class="hsp-label">Winlog</span>
                <span v-for="ch in hostSensorsPanel(selected).channelChips" :key="ch" class="hsp-chip soft">{{ ch }}</span>
              </div>
              <div v-if="healthChips(selected).length" class="hsp-row hsp-chips">
                <span class="hsp-label">运行</span>
                <span v-for="c in healthChips(selected)" :key="'hc-' + c.k" class="hsp-chip" :class="{ warn: c.warn }" :title="c.title || ''">{{ c.k }} {{ c.v }}</span>
              </div>
              <div v-if="hostSensorsPanel(selected).byKindLine" class="hsp-row mono sm muted">outbox {{ hostSensorsPanel(selected).byKindLine }}</div>
              <p v-if="agentDriftLine(selected)" class="hsp-drift">{{ agentDriftLine(selected) }}</p>
              <ul v-if="hostSensorsPanel(selected).advise?.length" class="hsp-advise">
                <li v-for="(a, i) in hostSensorsPanel(selected).advise" :key="i">{{ a }}</li>
              </ul>
            </div>
          </div>
        </header>

        <div class="snap-shell">
          <nav class="host-group-nav">
            <button
              v-for="g in HOST_TAB_GROUPS"
              :key="g.id"
              type="button"
              class="host-group-btn"
              :class="{ on: hostTabGroup === g.id }"
              @click="selectHostGroup(g.id)"
            >{{ g.label }}</button>
          </nav>
          <nav v-if="hostTabGroup !== 'remote'" class="mod-tabs bar">
            <button
              v-for="m in hostGroupMods"
              :key="m"
              type="button"
              class="mod-tab"
              :class="{ on: module === m }"
              @click="loadSnap(m)"
            >{{ modLabel(m) }}</button>
          </nav>

          <div v-if="hostTabGroup === 'remote'" class="host-remote-wrap panel">
            <div class="host-remote-hero">
              <div class="host-remote-hero-main">
                <h2>应急远程管理</h2>
                <p class="hint">经 Agent 指令通道运维（非 RDP）：Live Query 表 · 只读文件/注册表 · 白名单命令 · 交互 Shell。终端需<strong>在线</strong>，策略开启「远程运维」；下发需管理员。</p>
                <div class="host-remote-steps">
                  <span>① Live Query</span>
                  <span>② 读盘/注册表</span>
                  <span>③ Shell / 命令</span>
                </div>
              </div>
              <div class="host-remote-hero-aside">
                <span class="sync-pill lg" :class="{ on: selected.online }">
                  <i class="sync-dot" />
                  {{ selected.online ? '可下发指令' : '离线 · 仅可查看历史' }}
                </span>
                <span v-if="hostRemoteBusy" class="hr-busy-pill">执行中…</span>
              </div>
            </div>
            <nav class="host-remote-subnav" aria-label="远程运维功能">
              <button
                v-for="t in HOST_REMOTE_TABS"
                :key="t.id"
                type="button"
                class="hr-tab"
                :class="{ on: hostRemoteSubTab === t.id }"
                @click="hostRemoteSubTab = t.id"
              >
                <span class="hr-tab-label">{{ t.label }}</span>
                <span class="hr-tab-hint">{{ t.hint }}</span>
              </button>
            </nav>
            <div v-show="hostRemoteSubTab === 'files'" class="host-remote-panel hr-fs-panel">
              <div class="host-remote-toolbar">
                <input v-model="hostRemoteFsPath" class="field mono grow" placeholder="C:\" @keyup.enter="hostRemoteFsBrowse" />
                <button type="button" class="btn sm" :disabled="!hostRemoteFsPath || hostRemoteBusy" @click="hostRemoteFsUp">上级</button>
                <button type="button" class="btn sm primary" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteFsBrowse">刷新</button>
                <button type="button" class="btn sm" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteFsRead">读文件</button>
                <button type="button" class="btn sm" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteFsLoadVolumes">重新获取盘符</button>
              </div>
              <p v-if="hostRemoteFsHint" class="hint sm">{{ hostRemoteFsHint }}</p>
              <div class="hr-fs-explorer">
                <aside class="hr-fs-tree">
                  <div class="hr-fs-tree-hd">盘符 / 目录</div>
                  <p v-if="!hostRemoteFsTree.length" class="empty sm">{{ selected.online ? '正在读取盘符…' : '终端离线，无法列盘符' }}</p>
                  <ul v-else class="hr-fs-tree-ul">
                    <li v-for="row in hostRemoteFsTree" :key="row.node.path">
                      <button
                        type="button"
                        class="hr-fs-node"
                        :class="{ on: hostRemoteFsSamePath(hostRemoteFsPath, row.node.path) }"
                        :style="{ paddingLeft: (8 + row.depth * 14) + 'px' }"
                        :disabled="hostRemoteBusy"
                        @click="hostRemoteFsToggle(row.node)"
                      >
                        <i class="hr-fs-caret">{{ row.node.expanded ? '▼' : '▶' }}</i>
                        <span class="hr-fs-node-name">{{ row.node.label }}</span>
                        <em v-if="row.node.child_count != null">{{ row.node.child_count }} 项</em>
                      </button>
                    </li>
                  </ul>
                </aside>
                <div class="hr-fs-main">
                  <p class="hr-fs-crumb mono">
                    {{ hostRemoteFsPath || '未选择' }}
                    <span v-if="hostRemoteFsEntries.length"> · {{ hostRemoteFsEntries.length }} 项</span>
                    <span v-if="hostRemoteFsDirCount"> · 目录 {{ hostRemoteFsDirCount }}</span>
                    <span v-if="hostRemoteFsFileCount"> · 文件 {{ hostRemoteFsFileCount }}</span>
                  </p>
                  <p v-if="hostRemoteFsTruncated" class="hint sm warn-hint">目录项过多，仅显示前 200 条</p>
                  <table v-if="hostRemoteFsEntries.length" class="host-remote-cmd-table hr-fs-table">
                    <thead><tr><th>名称</th><th>类型</th><th>大小 / 项数</th><th></th></tr></thead>
                    <tbody>
                      <tr v-for="e in hostRemoteFsEntries" :key="e.name" class="hr-fs-row" @dblclick="hostRemoteFsEnter(e)">
                        <td><span class="hr-fs-icon">{{ e.dir ? '📁' : '📄' }}</span>{{ e.name }}</td>
                        <td>{{ e.dir ? '目录' : '文件' }}</td>
                        <td>{{ e.dir ? (e.child_count != null ? `${e.child_count} 项` : '目录') : hostRemoteFmtSize(e.size) }}</td>
                        <td>
                          <button type="button" class="btn-text" @click="hostRemoteFsEnter(e)">{{ e.dir ? '进入' : '预览' }}</button>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                  <p v-else class="empty sm">点左侧盘符展开目录</p>
                  <pre v-if="hostRemoteFsPreview" class="host-remote-pre">{{ hostRemoteFsPreview }}</pre>
                </div>
              </div>
            </div>
            <div v-show="hostRemoteSubTab === 'reg'" class="host-remote-panel hr-reg-panel">
              <div class="host-remote-toolbar">
                <select v-model="hostRemoteReg.hive" class="field">
                  <option value="HKLM">HKLM</option>
                  <option value="HKCU">HKCU</option>
                  <option value="HKU">HKU</option>
                  <option value="HKCR">HKCR</option>
                </select>
                <input v-model="hostRemoteReg.key" class="field mono grow" placeholder="SOFTWARE\..." @keyup.enter="hostRemoteRegLoad" />
                <input v-model="hostRemoteReg.value" class="field" placeholder="值名（留空列全部）" @keyup.enter="hostRemoteRegLoad" />
                <button type="button" class="btn sm" :disabled="!hostRemoteReg.key || hostRemoteBusy" @click="hostRemoteRegUp">上级</button>
                <button type="button" class="btn sm primary" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteRegLoad">读取</button>
              </div>
              <div class="hr-reg-shortcuts">
                <button
                  v-for="s in HOST_REG_SHORTCUTS"
                  :key="s.label"
                  type="button"
                  class="hr-reg-chip"
                  @click="hostRemoteRegApplyShortcut(s)"
                >{{ s.label }}</button>
              </div>
              <p v-if="hostRemoteRegBreadcrumb" class="hr-reg-crumb mono">{{ hostRemoteRegBreadcrumb }}</p>
              <div v-if="hostRemoteRegResult" class="hr-reg-body">
                <section v-if="hostRemoteRegSubkeys.length" class="hr-reg-section">
                  <h4>子键 <span class="muted">({{ hostRemoteRegSubkeys.length }})</span></h4>
                  <div class="hr-reg-subkey-list">
                    <button
                      v-for="sk in hostRemoteRegSubkeys"
                      :key="sk"
                      type="button"
                      class="hr-reg-subkey"
                      @click="hostRemoteRegOpenSubkey(sk)"
                    >{{ sk }}</button>
                  </div>
                </section>
                <section v-if="hostRemoteRegSingleValue" class="hr-reg-section">
                  <h4>值 · {{ hostRemoteRegSingleValue.name }}</h4>
                  <dl class="hr-reg-dl">
                    <div><dt>类型</dt><dd>{{ hostRemoteRegSingleValue.type }}</dd></div>
                    <div><dt>数据</dt><dd class="mono hr-reg-data">{{ hostRemoteRegSingleValue.data }}</dd></div>
                  </dl>
                </section>
                <section v-else-if="hostRemoteRegValues.length" class="hr-reg-section">
                  <h4>值 <span class="muted">({{ hostRemoteRegValues.length }}{{ hostRemoteRegResult.truncated ? '+' : '' }})</span></h4>
                  <table class="host-remote-cmd-table hr-reg-val-table">
                    <thead><tr><th>名称</th><th>类型</th><th>数据</th></tr></thead>
                    <tbody>
                      <tr v-for="v in hostRemoteRegValues" :key="v.name">
                        <td class="mono">{{ v.name }}</td>
                        <td>{{ v.type }}</td>
                        <td class="mono hr-reg-data">{{ v.data || v.data_hex || '—' }}</td>
                      </tr>
                    </tbody>
                  </table>
                </section>
                <p v-if="hostRemoteRegResult.truncated" class="hint sm">值过多，仅显示部分</p>
              </div>
              <p v-else class="empty sm">只读查询，不会修改注册表</p>
            </div>
            <div v-show="hostRemoteSubTab === 'livequery'" class="host-remote-panel hr-lq-panel">
              <p class="hint sm">
                按需向<strong>在线终端</strong>拉取只读资产表（进程、服务、监听端口、任务等），类似 Osquery 的「选表查询」。
                不是在终端里跑 Osquery / SQL；返回的是 Agent 现场采集结果。
              </p>
              <div class="host-remote-toolbar">
                <select v-model="hostLiveQueryTable" class="field">
                  <option v-for="t in hostLiveQueryTableOptions" :key="t.name" :value="t.name">
                    {{ t.name }}<template v-if="t.osquery_analog"> · ≈ {{ t.osquery_analog }}</template>
                  </option>
                </select>
                <input v-model.number="hostLiveQueryLimit" type="number" min="10" max="500" class="field" style="max-width:6rem" title="行数上限" />
                <button type="button" class="btn sm primary" :disabled="!selected.online || hostRemoteBusy" @click="hostLiveQueryRun">查询</button>
                <button type="button" class="btn sm" :disabled="!hostLiveQueryRows.length" @click="hostLiveQueryExport">导出 JSON</button>
              </div>
              <p v-if="hostLiveQueryMeta" class="hint sm mono">
                {{ hostLiveQueryMeta.table }} · {{ hostLiveQueryMeta.row_count ?? hostLiveQueryRows.length }} 行 · {{ hostLiveQueryMeta.schema || 'forensic_v1' }}
              </p>
              <div v-if="hostLiveQueryRows.length" class="hr-lq-table-wrap">
                <table class="host-remote-cmd-table hr-lq-table">
                  <thead>
                    <tr>
                      <th v-for="col in hostLiveQueryCols" :key="col">{{ col }}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(row, ri) in hostLiveQueryRows" :key="ri">
                      <td v-for="col in hostLiveQueryCols" :key="col" class="mono sm">{{ hostLiveQueryCell(row, col) }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p v-else class="empty sm">{{ selected.online ? '选择表并点击查询' : '终端离线' }}</p>
              <div class="panel pad" style="margin-top:12px">
                <div class="panel-hd" style="display:flex;justify-content:space-between;align-items:center">
                  <h4>Live Query 审计</h4>
                  <button type="button" class="btn sm" @click="loadLiveQueryAudit">刷新</button>
                </div>
                <p class="hint sm">谁查了什么（来自 agent_audit · command:live_query）</p>
                <table v-if="liveQueryAuditItems.length">
                  <thead><tr><th>时间</th><th>操作者</th><th>参数</th></tr></thead>
                  <tbody>
                    <tr v-for="a in liveQueryAuditItems" :key="a.id">
                      <td class="sm">{{ fmtTime(a.created_at) }}</td>
                      <td class="mono sm">{{ a.actor || '—' }}</td>
                      <td class="mono sm">{{ a.detail }}</td>
                    </tr>
                  </tbody>
                </table>
                <p v-else class="empty sm">暂无本机 Live Query 记录</p>
              </div>
            </div>
            <div v-show="hostRemoteSubTab === 'cmd'" class="host-remote-panel">
              <p class="hint sm">第二阶段：单条命令，Agent 侧白名单 + 危险关键字拦截；输出记录在下方与会话历史。</p>
              <textarea v-model="hostRemoteCmdLine" class="field mono host-remote-cmd-in" rows="3" placeholder="dir C:\Users" />
              <button type="button" class="btn sm primary" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteRunCmd">执行</button>
              <pre v-if="hostRemoteCmdOut" class="host-remote-pre">{{ hostRemoteCmdOut }}</pre>
              <div v-if="hostRemoteCmdLog.length" class="host-remote-cmd-log">
                <h4>会话历史</h4>
                <div v-for="(ln, i) in hostRemoteCmdLog" :key="i" class="host-remote-log-line">
                  <em>{{ ln.at }}</em> <code>{{ ln.cmd }}</code>
                </div>
              </div>
            </div>
            <div v-show="hostRemoteSubTab === 'shell'" class="host-remote-panel hr-shell-panel">
              <div class="hr-shell-layout">
                <div class="hr-shell-card">
                  <div class="hr-shell-hd">
                    <div class="hr-shell-status">
                      <i class="hr-shell-led" :class="hostRemoteShellPhase" />
                      <span>{{ hostRemoteShellStatusLabel }}</span>
                      <code v-if="hostRemoteShellId" class="mono hr-shell-sid">{{ hostRemoteShellId.slice(0, 12) }}…</code>
                    </div>
                    <div class="hr-shell-actions">
                      <button
                        type="button"
                        class="btn sm primary"
                        :disabled="hostRemoteShellConnectDisabled"
                        @click="hostRemoteShellStart"
                      >
                        {{ hostRemoteShellPhase === 'connecting' ? '连接中…' : (hostRemoteShellPhase === 'live' ? '已连接' : '连接 Shell') }}
                      </button>
                      <button type="button" class="btn sm" :disabled="!hostRemoteShellId && hostRemoteShellPhase !== 'connecting'" @click="() => hostRemoteShellStop(false)">断开</button>
                      <button type="button" class="btn sm" :disabled="!hostRemoteShellLines.length" @click="hostRemoteShellClear">清屏</button>
                    </div>
                  </div>
                  <p v-if="hostRemoteShellHint" class="hr-shell-banner" :class="hostRemoteShellHintKind">{{ hostRemoteShellHint }}</p>
                  <div ref="hostRemoteShellViewRef" class="hr-shell-body">
                    <div v-if="!hostRemoteShellLines.length" class="hr-shell-empty">
                      <p>尚未建立会话</p>
                      <p class="muted">连接后输入命令；中文 Windows 输出已按 GBK 解码。右侧可点常用命令。</p>
                      <p v-if="!isAdmin" class="warn-hint">当前账号非管理员，无法下发 Shell 指令，请使用 admin 登录。</p>
                      <p v-else-if="!selected.online" class="warn-hint">终端离线，按钮不可用。</p>
                    </div>
                    <div
                      v-for="(ln, i) in hostRemoteShellLines"
                      :key="i"
                      class="hr-shell-line"
                      :class="ln.kind || 'out'"
                    >{{ ln.text }}</div>
                  </div>
                  <div class="hr-shell-inputbar">
                    <span class="hr-shell-prompt">&gt;</span>
                    <input
                      ref="hostRemoteShellInputRef"
                      v-model="hostRemoteShellInput"
                      class="field mono grow hr-shell-input"
                      :disabled="!hostRemoteShellId || hostRemoteShellPhase === 'connecting'"
                      placeholder="连接后输入命令，Enter 发送"
                      @keyup.enter="hostRemoteShellSend"
                    />
                    <button
                      type="button"
                      class="btn sm primary"
                      :disabled="!hostRemoteShellId || hostRemoteShellPhase === 'connecting'"
                      @click="hostRemoteShellSend"
                    >
                      发送
                    </button>
                  </div>
                </div>
                <aside class="hr-shell-aside">
                  <h4>常用命令</h4>
                  <p class="hint sm">需先连接 Shell；危险命令仍会被 Agent 拦截。</p>
                  <button
                    v-for="c in HOST_SHELL_QUICK"
                    :key="c"
                    type="button"
                    class="btn sm block hr-shell-quick"
                    :disabled="!hostRemoteShellId || hostRemoteShellPhase === 'connecting'"
                    @click="hostRemoteShellQuick(c)"
                  >{{ c }}</button>
                </aside>
              </div>
              <p class="hint sm hr-shell-foot">会话默认 15 分钟空闲超时，单 Agent 最多 3 路；轮询拉取输出（约 1–2 秒）。</p>
            </div>
            <div v-show="hostRemoteSubTab === 'ops'" class="host-remote-grid">
              <section class="host-remote-card">
                <h4>调查入口</h4>
                <div class="host-remote-links">
                  <button type="button" class="btn sm" @click="openSelectedHostThreats">本机威胁事件</button>
                  <button type="button" class="btn sm" @click="openInvestigateForHost">日志调查</button>
                  <button type="button" class="btn sm" @click="goMenu('timeline'); tlAgentId = selected?.agent_id || ''; loadTimeline()">主机时间线</button>
                  <button type="button" class="btn sm primary" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteAction('refresh_modules')">立即刷新采集</button>
                </div>
              </section>
              <section class="host-remote-card">
                <h4>网络与采集</h4>
                <p class="hint sm">隔离后仍保留 DNS/管理端通道，便于继续下发解除指令。</p>
                <div class="host-remote-btns">
                  <button type="button" class="btn sm danger-outline" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteAction('isolate_network')">网络隔离</button>
                  <button type="button" class="btn sm" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteAction('unisolate_network')">解除隔离</button>
                </div>
              </section>
              <section class="host-remote-card">
                <h4>结束进程</h4>
                <label class="hr-field">
                  <span>PID</span>
                  <input v-model="hostRemoteForm.pid" class="field" placeholder="如 9448" />
                </label>
                <button type="button" class="btn sm danger" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteAction('kill_process')">结束进程</button>
              </section>
              <section class="host-remote-card">
                <h4>隔离文件</h4>
                <label class="hr-field">
                  <span>完整路径</span>
                  <input v-model="hostRemoteForm.path" class="field mono" placeholder="C:\Users\...\file.exe" />
                </label>
                <button type="button" class="btn sm danger-outline" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteAction('quarantine_file')">隔离文件</button>
              </section>
              <section class="host-remote-card">
                <h4>内存 YARA 扫描</h4>
                <label class="hr-field">
                  <span>PID（留空扫前 40 进程）</span>
                  <input v-model="hostRemoteForm.scanPid" class="field" placeholder="可选" />
                </label>
                <button type="button" class="btn sm" :disabled="!selected.online || hostRemoteBusy" @click="hostRemoteAction('scan_memory')">开始扫描</button>
              </section>
              <section class="host-remote-card">
                <h4>维护</h4>
                <p class="hint sm">卸载会停止 Agent 服务；仅应急确认后使用。</p>
                <button type="button" class="btn sm" :disabled="!selected.online" @click="uninstallHost(selected)">远程卸载 Agent</button>
              </section>
              <section class="host-remote-card wide">
                <div class="host-remote-cmd-hd">
                  <h4>指令记录</h4>
                  <button type="button" class="btn sm" @click="loadHostRemoteCommands">刷新</button>
                </div>
                <table v-if="hostRemoteCommands.length" class="host-remote-cmd-table">
                  <thead>
                    <tr><th>时间</th><th>动作</th><th>状态</th><th>参数</th><th>结果</th><th></th></tr>
                  </thead>
                  <tbody>
                    <tr v-for="c in hostRemoteCommands" :key="c.id">
                      <td>{{ fmtTime(c.updated_at || c.created_at) }}</td>
                      <td>{{ actionLabel(c.action) }}</td>
                      <td><span class="cmd-st" :data-s="c.status">{{ cmdStatusLabel(c.status) }}</span></td>
                      <td class="muted mono">{{ shortJson(c.params_json) }}</td>
                      <td class="muted" :title="c.result_json">{{ friendlyCmdResult(c.action, c.result_json) }}</td>
                      <td>
                        <button
                          v-if="c.action === 'quarantine_file' && c.status === 'done'"
                          type="button"
                          class="btn-text"
                          @click="restoreQuarantined(c)"
                        >回滚隔离</button>
                      </td>
                    </tr>
                  </tbody>
                </table>
                <p v-else class="empty sm">暂无远程指令记录</p>
              </section>
            </div>
          </div>

          <div v-if="hostTabGroup !== 'remote'" class="snap-flags">
            <span v-for="f in snapStats.flags" :key="f.k" class="sflag" :data-t="f.tone">{{ f.label }}</span>
            <span class="sflag muted">共 {{ snapStats.total }} 条 · 同步 {{ fmtTime(snap?.collected_at) }}</span>
            <span v-if="columns.length" class="sflag muted">展示 {{ columns.length }} 列</span>
          </div>
          <div class="snap-viewbar" v-if="hostTabGroup !== 'remote' && module !== 'sysinfo' && hostTabGroup === 'runtime'">
            <button type="button" class="tl-fchip" :class="{ on: snapView === 'all' }" @click="snapView = 'all'">全部</button>
            <button type="button" class="tl-fchip" :class="{ on: snapView === 'risk' }" data-k="file" @click="snapView = 'risk'">
              仅可疑 <em>{{ snapRiskCount }}</em>
            </button>
            <button type="button" class="tl-fchip" :class="{ on: snapView === 'hide_noise' }" @click="snapView = 'hide_noise'">
              隐藏系统噪声
            </button>
            <span class="meta">运行态筛选 · 告警/时间线请到「检测」分区</span>
          </div>
          <div class="snap-viewbar" v-else-if="hostTabGroup !== 'remote' && module !== 'sysinfo' && hostTabGroup === 'inventory'">
            <span class="meta">资产清单：软件 / 补丁 / 监听端口 / 用户 · 与检测态分离</span>
          </div>

          <div v-if="hostTabGroup !== 'remote'" class="snap-work has-detail">
            <div class="panel snap-list">
              <div class="panel-hd">
                <div>
                  <h3>{{ modLabel(module) }}</h3>
                  <span class="meta" v-if="snap">
                    最近同步 {{ fmtTime(snap.collected_at) }} · {{ filteredSnapRows.length }} / {{ (snap.items || []).length }} 条
                    · {{ liveOk ? `已连接 · ${liveAgo}` : '同步中' }}
                  </span>
                </div>
                <input
                  v-if="module !== 'sysinfo'"
                  v-model="snapQ"
                  class="search"
                  placeholder="搜索名称 / 路径 / 命令 / DLL…"
                />
              </div>

              <div v-if="snapLoading" class="empty">加载中…</div>
              <div v-else-if="snapError" class="empty err">
                <p>{{ snapError }}</p>
                <p class="hint">终端需在线并完成至少一轮上报后才有该模块快照</p>
              </div>
              <div v-else-if="module === 'sysinfo'" class="sysinfo-grid">
                <div v-for="(v, k) in (snap?.items?.[0] || {})" :key="k" class="si-item">
                  <label>{{ colLabel(k) }}</label>
                  <div>{{ cell({ [k]: v }, k) }}</div>
                </div>
                <p v-if="!(snap?.items || []).length" class="empty">暂无系统信息</p>
              </div>
              <div v-else class="table-scroll snap-table">
                <table>
                  <thead>
                    <tr>
                      <th v-for="c in columns" :key="c">{{ colLabel(c) }}</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="(row, i) in filteredSnapRows"
                      :key="i"
                      class="row-click"
                      :class="{ active: snapRow === row }"
                      @click="snapRow = row"
                    >
                      <td v-for="c in columns" :key="c" :title="cell(row, c)">{{ cell(row, c) }}</td>
                    </tr>
                  </tbody>
                </table>
                <p v-if="!(snap?.items || []).length" class="empty">该模块暂无数据（终端尚未上报或采集为空）</p>
                <p v-else-if="!filteredSnapRows.length" class="empty">无匹配结果</p>
              </div>
            </div>

            <aside class="panel snap-detail">
              <template v-if="module === 'sysinfo' && (snap?.items?.[0])">
                <div class="sd-hd">
                  <div>
                    <b>系统信息</b>
                    <small>完整字段</small>
                  </div>
                </div>
                <dl class="sd-dl">
                  <div v-for="(v, k) in snap.items[0]" :key="k">
                    <dt>{{ colLabel(k) }}</dt>
                    <dd>{{ v == null || v === '' ? '—' : String(v) }}</dd>
                  </div>
                </dl>
              </template>
              <template v-else-if="snapRow">
                <div class="sd-hd">
                  <div>
                    <b>{{ rowTitle(snapRow) }}</b>
                    <small>{{ modLabel(module) }} · 共 {{ Object.keys(snapRow).length }} 个字段</small>
                  </div>
                  <button type="button" class="icon-x" @click="snapRow = null">×</button>
                </div>
                <div class="sd-groups">
                  <div v-for="g in detailGroups(snapRow)" :key="g.title" class="sd-group">
                    <h4>{{ g.title }}</h4>
                    <dl class="sd-dl compact-gap">
                      <div v-for="(v, k) in g.fields" :key="k">
                        <dt>{{ colLabel(k) }}</dt>
                        <dd :title="String(v ?? '')">{{ formatDetail(v) }}</dd>
                      </div>
                    </dl>
                  </div>
                </div>
                <div class="sd-actions" v-if="snapRow && (module === 'process' || module === 'file')">
                  <button type="button" class="btn sm primary block" @click="hostRemoteFromRow(snapRow)">远程管理 →</button>
                </div>
                <div class="sd-actions" v-if="module === 'process' && snapRow">
                  <h4>进程关系</h4>
                  <dl class="sd-dl compact-gap">
                    <div>
                      <dt>父进程</dt>
                      <dd>
                        <button
                          v-if="snapRow.parent_name || snapRow.ppid"
                          type="button"
                          class="btn-text"
                          @click="jumpToPid(snapRow.ppid)"
                        >{{ snapRow.parent_name || '—' }} ({{ snapRow.ppid }})</button>
                        <span v-else>—</span>
                      </dd>
                    </div>
                    <div v-if="snapRow.risk_tags">
                      <dt>风险标签</dt>
                      <dd>{{ snapRow.risk_tags }}</dd>
                    </div>
                    <div v-if="snapRow.module_count != null">
                      <dt>模块数</dt>
                      <dd>共 {{ snapRow.module_count }} · 第三方/可疑 {{ snapRow.module_third_count || processDlls.length }}</dd>
                    </div>
                  </dl>
                  <div v-if="childProcesses.length" class="child-list">
                    <small>子进程 ({{ childProcesses.length }})</small>
                    <button
                      v-for="c in childProcesses"
                      :key="c.pid"
                      type="button"
                      class="child-row"
                      @click="snapRow = c"
                    >
                      <b>{{ c.name }}</b>
                      <em>PID {{ c.pid }}</em>
                    </button>
                  </div>
                  <div v-if="processDlls.length" class="dll-list">
                    <small>已加载 DLL（已过滤 System32）· {{ processDlls.length }} · 点击查看详情</small>
                    <button
                      v-for="(d, i) in processDlls"
                      :key="i"
                      type="button"
                      class="dll-row"
                      :class="{ hot: d.hot || d.unsigned, on: selectedDll === d }"
                      @click="selectedDll = selectedDll === d ? null : d"
                    >
                      <b :title="d.path">{{ d.name || '—' }}</b>
                      <em :title="d.path">{{ shortPath(d.path || '') }}</em>
                      <span v-if="d.hot" class="sev" data-s="high">可疑路径</span>
                      <span v-else-if="d.unsigned" class="sev" data-s="medium">未签名</span>
                      <span v-else-if="d.signed" class="sev" data-s="info">{{ d.signed }}</span>
                    </button>
                    <div v-if="selectedDll" class="dll-detail">
                      <h5>{{ selectedDll.name || '模块详情' }}</h5>
                      <dl class="sd-dl compact-gap">
                        <div><dt>模块名</dt><dd>{{ selectedDll.name || '—' }}</dd></div>
                        <div><dt>完整路径</dt><dd class="mono" :title="selectedDll.path">{{ selectedDll.path || '—' }}</dd></div>
                        <div><dt>签名</dt><dd>
                          <span class="sev" :data-s="selectedDll.unsigned ? 'medium' : (selectedDll.signed === 'Valid' ? 'info' : 'low')">
                            {{ selectedDll.signed || '—' }}
                          </span>
                        </dd></div>
                        <div v-if="selectedDll.signer"><dt>签名者</dt><dd :title="selectedDll.signer">{{ selectedDll.signer }}</dd></div>
                        <div v-if="selectedDll.company"><dt>公司</dt><dd>{{ selectedDll.company }}</dd></div>
                        <div v-if="selectedDll.file_version"><dt>文件版本</dt><dd>{{ selectedDll.file_version }}</dd></div>
                        <div v-if="selectedDll.size"><dt>大小</dt><dd>{{ fmtSize(selectedDll.size) }}</dd></div>
                        <div v-if="selectedDll.sha256"><dt>SHA256</dt><dd class="mono" :title="selectedDll.sha256">{{ selectedDll.sha256 }}</dd></div>
                        <div v-if="selectedDll.hot"><dt>风险</dt><dd><span class="sev" data-s="high">可疑路径</span></dd></div>
                      </dl>
                      <div class="row" style="margin-top:8px;gap:8px">
                        <button v-if="selectedDll.path" type="button" class="btn sm" @click="copyText(selectedDll.path)">复制路径</button>
                        <button v-if="selectedDll.sha256" type="button" class="btn sm" @click="copyText(selectedDll.sha256)">复制哈希</button>
                      </div>
                    </div>
                  </div>
                  <p v-else-if="snapRow.module_count" class="hint">该进程模块均为系统目录 DLL，或尚未完成模块采集（请「立即刷新」）。</p>
                </div>
                <div class="sd-actions" v-if="(module === 'service' || module === 'task') && snapRow">
                  <h4>风险研判</h4>
                  <dl class="sd-dl compact-gap">
                    <div><dt>风险分</dt><dd>{{ snapRow.risk_score ?? 0 }}</dd></div>
                    <div><dt>标签</dt><dd>{{ snapRow.risk_tags || (snapRow.noise ? '系统噪声' : '—') }}</dd></div>
                    <div><dt>系统噪声</dt><dd>{{ snapRow.noise ? '是（可隐藏）' : '否' }}</dd></div>
                  </dl>
                </div>
                <div class="sd-actions" v-if="(module === 'service' || module === 'network') && snapRow?.pid">
                  <button type="button" class="btn sm" @click="jumpToPid(snapRow.pid)">跳转到进程 PID {{ snapRow.pid }}</button>
                </div>
                <div class="sd-actions" v-if="hostTabGroup === 'runtime' && rowRelatedAlerts(snapRow).length">
                  <h4>跳转检测</h4>
                  <button
                    v-for="e in rowRelatedAlerts(snapRow)"
                    :key="e.id"
                    type="button"
                    class="ha-row"
                    @click="openEvent(e)"
                  >
                    <span class="sev" :data-s="e.severity">{{ sevLabel(e.severity) }}</span>
                    <span class="strong">{{ e.title }}</span>
                  </button>
                </div>
              </template>
              <div v-else class="snap-sum">
                <div class="sd-hd">
                  <div>
                    <b>{{ modLabel(module) }} 模块摘要</b>
                    <small>{{ hostTabGroup === 'inventory' ? '资产字段概览' : '点击左侧行查看完整字段' }}</small>
                  </div>
                </div>
                <div class="ss-kpis">
                  <div><span>条目</span><strong>{{ snapStats.total }}</strong></div>
                  <div v-if="snapStats.unsigned != null"><span>未签名</span><strong class="c-danger">{{ snapStats.unsigned }}</strong></div>
                  <div v-if="snapStats.hotpath != null"><span>可疑路径</span><strong class="c-warn">{{ snapStats.hotpath }}</strong></div>
                  <div v-if="snapStats.admins != null"><span>管理员身份</span><strong>{{ snapStats.admins }}</strong></div>
                  <div v-if="snapStats.fields"><span>字段数</span><strong>{{ snapStats.fields }}</strong></div>
                </div>
                <div v-if="hostTabGroup === 'runtime' && hostAlerts.length" class="ss-list">
                  <h4>检测入口</h4>
                  <button type="button" class="ss-row" @click="openSelectedHostThreats">
                    <span class="sev" data-s="high">威胁</span>
                    <b>本机威胁事件 {{ hostAlerts.length }}</b>
                    <small>打开检测 → 威胁事件</small>
                  </button>
                  <button type="button" class="ss-row" @click="goMenu('timeline'); tlAgentId = selected?.agent_id || ''; loadTimeline()">
                    <span class="sev" data-s="info">时间线</span>
                    <b>主机时间线</b>
                    <small>打开检测 → 主机时间线</small>
                  </button>
                </div>
                <div v-if="snapStats.hotRows.length" class="ss-list">
                  <h4>关注项</h4>
                  <button
                    v-for="(r, i) in snapStats.hotRows"
                    :key="i"
                    type="button"
                    class="ss-row"
                    @click="snapRow = r.row"
                  >
                    <span class="sev" :data-s="r.sev">{{ r.tag }}</span>
                    <b>{{ r.title }}</b>
                    <small>{{ r.sub }}</small>
                  </button>
                </div>
                <div v-if="snapStats.sampleRows.length" class="ss-list">
                  <h4>最近条目</h4>
                  <button
                    v-for="(r, i) in snapStats.sampleRows"
                    :key="'s'+i"
                    type="button"
                    class="ss-row"
                    @click="snapRow = r.row"
                  >
                    <span class="sev" data-s="info">条目</span>
                    <b>{{ r.title }}</b>
                    <small>{{ r.sub }}</small>
                  </button>
                </div>
                <p v-else-if="!snapStats.hotRows.length" class="empty sm">本模块暂无高亮项，可在左侧点行查看详情</p>
                <div class="ss-acts">
                  <button type="button" class="btn sm" @click="openTimelineFor(selected.agent_id)">本机时间线</button>
                  <button type="button" class="btn sm" @click="openHostThreats(selected)">本机威胁</button>
                </div>
              </div>
            </aside>
          </div>
        </div>
      </section>

      <!-- ========== 部署 ========== -->
      <section v-else-if="page === 'deploy'" class="page">
        <header class="page-hd">
          <div>
            <h1>部署运营</h1>
            <p class="desc">静默安装包内嵌平台地址与接入密钥</p>
          </div>
        </header>
        <div class="deploy-grid">
          <article class="panel pad">
            <h3>下载安装包</h3>
            <p>含 forensic-agent.exe、agent.json、install.vbs（用户态采集，不含内核驱动）；安装结束会弹窗提示结果。</p>
            <div v-if="release" class="rel-box" :class="'rel-' + release.status">
              <div class="rel-hd">
                <span class="pill" :class="{ on: release.is_latest }">{{ releaseLabel }}</span>
                <b v-if="release.version">v{{ release.version }}</b>
                <span v-if="release.build_id" class="muted mono">{{ release.build_id }}</span>
              </div>
              <div v-if="release.exe_sha256" class="rel-line">SHA256 <code class="mono">{{ release.exe_sha256.slice(0, 24) }}…</code></div>
              <div v-if="release.build_time" class="rel-line">构建时间 {{ release.build_time }}</div>
              <div v-if="release.protocol_max" class="rel-line">协议 v{{ release.protocol_min }}–v{{ release.protocol_max }} · 能力 {{ (release.capabilities || []).length }} 项</div>
              <div v-for="r in (release.reasons || [])" :key="r" class="rel-warn">{{ r }}</div>
              <div class="rel-act">
                <button type="button" class="btn" :disabled="releaseBusy || release.building || !release.go_available" @click="doBuildRelease">
                  {{ release.building ? '构建中…' : '重新构建 Agent' }}
                </button>
                <span v-if="!release.go_available" class="muted">服务器未检测到 Go</span>
              </div>
            </div>
            <button type="button" class="btn primary lg" :disabled="dlBusy" style="margin-top:12px" @click="doDownload">
              {{ dlBusy ? '下载中…' : (release && !release.is_latest ? '仍然下载（非最新）' : '下载静默安装包') }}
            </button>
            <p v-if="dlBusy && dlProgress" class="meta" style="margin-top:8px">{{ dlProgress }}</p>
            <p v-if="dlError" class="err-text">{{ dlError }}</p>
          </article>
          <article v-if="credSummary" class="panel pad">
            <h3>终端凭据</h3>
            <p>每台终端首次注册后获得专属凭据（仅存哈希），共享接入密钥只用于首次注册。</p>
            <div class="rel-line">终端 {{ credSummary.total }} 台 · 已用专属凭据 <b>{{ credSummary.with_secret }}</b> · 已吊销 <b>{{ credSummary.revoked }}</b></div>
            <div v-if="credSummary.total > credSummary.with_secret" class="rel-warn">
              {{ credSummary.total - credSummary.with_secret }} 台仍是旧版终端（共享密钥），升级 Agent 后自动迁移
            </div>
            <div class="rel-act">
              <button type="button" class="btn" :disabled="credBusy" @click="toggleSharedKey">
                {{ credSummary.allow_shared_key ? '禁止共享密钥上报' : '允许共享密钥上报' }}
              </button>
              <span class="muted">{{ credSummary.allow_shared_key ? '当前：兼容旧终端' : '当前：仅专属凭据可上报' }}</span>
            </div>
          </article>
          <article class="panel pad">
            <h3>安装步骤</h3>
            <ol>
              <li>解压到目标机任意目录</li>
              <li>右键 <code>install.vbs</code> → 以管理员身份运行</li>
              <li>完成后查看弹窗与 install.log</li>
              <li>服务 ForensicAgent 自动启动并回连</li>
              <li>卸载：管理员运行 <code>uninstall.bat</code></li>
            </ol>
          </article>
        </div>
      </section>

      <!-- ========== Agent 规则管理 ========== -->
      <section v-else-if="page === 'rules'" class="page rules-page">
        <header class="page-hd">
          <div>
            <h1>Agent 规则</h1>
            <p class="desc">检出规则 / 内存 YARA / 告警加白（抑制误报，与检测规则分开管理）</p>
          </div>
          <div class="hd-right">
            <template v-if="rulesSection === 'detect'">
              <button type="button" class="btn" @click="loadRules">刷新</button>
              <button type="button" class="btn primary" @click="startCreateRule">新增规则</button>
            </template>
            <template v-else-if="rulesSection === 'whitelist'">
              <button type="button" class="btn" @click="loadWhitelistOnly">刷新</button>
              <button type="button" class="btn sm" @click="goMenu('policy')">EDR 策略（完整）</button>
            </template>
            <button
              v-else
              type="button"
              class="btn primary"
              :disabled="memoryYaraBusy"
              @click="loadMemoryYara"
            >
              {{ memoryYaraBusy ? '加载中…' : '刷新规则包' }}
            </button>
          </div>
        </header>

        <nav class="rules-subnav" role="tablist" aria-label="规则分类">
          <button
            type="button"
            role="tab"
            class="rules-tab"
            :class="{ on: rulesSection === 'detect' }"
            :aria-selected="rulesSection === 'detect'"
            @click="rulesSection = 'detect'"
          >
            检出规则
            <span class="rules-tab-meta">{{ agentRules.length }} 条</span>
          </button>
          <button
            type="button"
            role="tab"
            class="rules-tab"
            :class="{ on: rulesSection === 'memory' }"
            :aria-selected="rulesSection === 'memory'"
            @click="openRulesMemorySection"
          >
            内存 YARA
            <span v-if="memoryYaraPack?.ok" class="rules-tab-meta">
              {{ memoryYaraPack.rule_count ?? (memoryYaraPack.items || []).length }} 字符串
            </span>
          </button>
          <button
            type="button"
            role="tab"
            class="rules-tab"
            :class="{ on: rulesSection === 'whitelist' }"
            :aria-selected="rulesSection === 'whitelist'"
            @click="openRulesWhitelistSection"
          >
            告警加白
            <span class="rules-tab-meta">{{ whitelistEnabledCount }}/{{ whitelist.length }}</span>
          </button>
        </nav>

        <div v-if="agentSyncManifest?.ok" class="agent-sync-wrap">
          <div class="agent-sync-bar">
            <span
              class="agent-sync-rev"
              title="sync_rev：服务端「下发版本号」。Agent 心跳/同步时带上本地 rev，若小于此值则拉取 EVM、策略、集成开关等；改规则或下方开关保存后会自动 +1。"
            >
              sync_rev <b class="mono">{{ agentSyncManifest.sync_rev }}</b>
            </span>
            <span class="muted mono" title="各配置块 hash 聚合">agg {{ agentSyncManifest.aggregate_hash }}</span>
            <span v-if="agentIntegrations?.server" class="muted sm" title="云端入库检测开关">
              云端：EVM {{ agentIntegrations.server.evm_ingest !== false ? '开' : '关' }}
              · LOLBin {{ agentIntegrations.server.lolbin_ingest !== false ? '开' : '关' }}
            </span>
            <button type="button" class="btn sm" :disabled="agentSyncBusy" @click="loadAgentSyncManifest">
              {{ agentSyncBusy ? '…' : '刷新摘要' }}
            </button>
            <button
              type="button"
              class="btn sm"
              :class="{ on: agentIntegrationsOpen }"
              @click="toggleAgentIntegrationsPanel"
            >
              端上能力开关
            </button>
            <button
              v-if="isAdmin"
              type="button"
              class="btn sm ghost"
              :disabled="agentSyncBumpBusy"
              title="不修改配置，仅递增 sync_rev，促使 Agent 尽快重新拉取"
              @click="manualBumpAgentSync"
            >
              {{ agentSyncBumpBusy ? '…' : '强制同步' }}
            </button>
          </div>
          <div v-if="agentIntegrationsOpen && agentIntegrations?.ok" class="agent-int-panel panel pad">
            <div class="agent-int-intro">
              <p>
                <span class="pill sm on">端上</span>
                改后 <code class="mono">sync_rev</code> +1，终端约 1–2 分钟内同步。
                <span class="pill sm cloud">云端</span>
                时间线入库后在服务端匹配，<strong>立即生效</strong>、与端上 EVM 独立。
              </p>
              <p v-if="!isAdmin" class="warn sm">需管理员账号才能修改开关。</p>
            </div>

            <details v-if="agentSyncManifest?.parts" class="agent-sync-parts">
              <summary>配置块摘要（policy / evm / memory_yara …）</summary>
              <div class="agent-sync-parts-grid">
                <div
                  v-for="(p, key) in agentSyncManifest.parts"
                  :key="key"
                  class="agent-sync-part-cell"
                  :title="JSON.stringify(p)"
                >
                  <span class="part-name">{{ key }}</span>
                  <code class="mono">{{ p.rev || p.hash }}</code>
                </div>
              </div>
            </details>

            <section
              v-for="grp in AGENT_INTEGRATION_GROUPS"
              :key="grp.id"
              class="agent-int-section"
            >
              <h4 class="agent-int-hd">{{ grp.title }}</h4>
              <p v-if="grp.hint" class="hint sm agent-int-grp-hint">{{ grp.hint }}</p>
              <div class="agent-int-cards">
                <div
                  v-for="key in grp.keys"
                  :key="'a-' + key"
                  class="agent-int-card"
                  :class="{ off: agentIntegrations.defaults?.[key] === false }"
                >
                  <label class="agent-int-switch" :title="key">
                    <input
                      type="checkbox"
                      :disabled="!isAdmin || agentIntegrationsBusy"
                      :checked="agentIntegrations.defaults?.[key] !== false"
                      @change="setAgentIntegration(key, $event.target.checked)"
                    />
                    <span class="agent-int-switch-ui" aria-hidden="true" />
                  </label>
                  <div class="agent-int-card-text">
                    <span class="agent-int-card-title">{{ agentIntegrations.labels?.[key] || key }}</span>
                    <code class="agent-int-card-key mono">{{ key }}</code>
                  </div>
                </div>
              </div>
            </section>

            <section class="agent-int-section agent-int-section-cloud">
              <h4 class="agent-int-hd">云端（服务端入库）</h4>
              <p class="hint sm">{{ agentIntegrations.server_note }}</p>
              <div class="agent-int-cards compact">
                <div
                  v-for="key in SERVER_DETECTION_UI_KEYS"
                  :key="'s-' + key"
                  class="agent-int-card"
                  :class="{ off: agentIntegrations.server?.[key] === false }"
                >
                  <label class="agent-int-switch" :title="key">
                    <input
                      type="checkbox"
                      :disabled="!isAdmin || agentIntegrationsBusy"
                      :checked="agentIntegrations.server?.[key] !== false"
                      @change="setServerDetection(key, $event.target.checked)"
                    />
                    <span class="agent-int-switch-ui" aria-hidden="true" />
                  </label>
                  <div class="agent-int-card-text">
                    <span class="agent-int-card-title">{{ agentIntegrations.labels?.[key] || key }}</span>
                    <code class="agent-int-card-key mono">{{ key }}</code>
                  </div>
                </div>
              </div>
            </section>

            <details class="agent-deploy-ref">
              <summary>互联网 / 大规模 Agent 在线 — 环境与容量参考</summary>
              <div class="agent-deploy-body">
                <div class="agent-deploy-cols">
                  <div>
                    <h5>基础环境</h5>
                    <ul>
                      <li><strong>公网入口</strong>：HTTPS（TLS 1.2+），建议 WAF + 限流；Agent 仅走 <code class="mono">/api/agent/*</code>，管理台独立域名或 IP 白名单。</li>
                      <li><strong>反向代理</strong>：Nginx / Caddy；长连接 SSE 需调大 <code class="mono">proxy_read_timeout</code>（建议 ≥300s）。</li>
                      <li><strong>应用</strong>：Python 3.10+，Uvicorn/Gunicorn 多 worker（CPU 核数或 2×核）；静态管理台可 CDN。</li>
                      <li><strong>Redis</strong>（推荐）：会话、去重、live 计数；配置见 <code class="mono">redis_config.json</code> / 环境变量。</li>
                      <li><strong>Elasticsearch</strong>（可选）：时间线/狩猎检索；无 ES 时核心告警仍走 SQLite。</li>
                      <li><strong>磁盘</strong>：<code class="mono">reports/agents.db</code> 与日志分区；时间线量大时单独数据盘，定期归档。</li>
                    </ul>
                  </div>
                  <div>
                    <h5>并发与在线规模（经验值）</h5>
                    <ul>
                      <li>默认心跳 <code class="mono">heartbeat_sec≈3</code>：1000 在线 ≈ <strong>330 次/秒</strong> 心跳；5000 在线 ≈ <strong>1600+ 次/秒</strong>。上万 Agent 建议策略里改为 <strong>15–30s</strong> 心跳。</li>
                      <li>时间线批量上报与快照：峰值取决于 ETW 开项；开满 <code class="mono">sensor-etw-proc</code> 类 info 进程会显著增流量，生产可关纯遥测、保留 LOLBin/EVM 相关。</li>
                      <li>内存 YARA / 全量 ETW：主要吃<strong>终端 CPU/内存</strong>；服务端按入库 QPS 扩容 worker 与 DB。</li>
                      <li><strong>SQLite 单写</strong>：适合百～数千 Agent；<strong>5000+ 长期在线</strong> 建议规划 PostgreSQL + 队列（当前代码以 SQLite 为主，需架构升级）。</li>
                    </ul>
                  </div>
                  <div>
                    <h5>安全与网络</h5>
                    <ul>
                      <li>Agent 安装包内嵌密钥，公网务必<strong>一机一密 / 定期轮换</strong>，禁用弱共享密钥。</li>
                      <li>出站：终端需能访问平台 <code class="mono">443</code>；无需 inbound 到终端。</li>
                      <li>关 <code class="mono">wmi_process</code> 可减 WMI 负载（默认关）；关 <code class="mono">winevent</code> 仅在有 ETW 时考虑。</li>
                    </ul>
                  </div>
                </div>
                <p class="hint sm">
                  以上为当前 Forensic Agent 架构下的部署参考，非硬性 SLA；实际上线前请用目标 Agent 数量做压测（心跳 + 时间线 + 规则 sync 各一轮）。
                </p>
              </div>
            </details>

            <p v-if="agentIntegrationsErr" class="err-text">{{ agentIntegrationsErr }}</p>
          </div>
        </div>

        <div v-show="rulesSection === 'detect'" class="rules-layout">
          <div class="panel fill">
            <div class="panel-hd">
              <h3>规则列表 ({{ filteredAgentRules.length }} / {{ agentRules.length }})</h3>
              <span class="meta">启用 {{ agentRules.filter(r => r.enabled).length }} 条</span>
            </div>
            <div class="rules-toolbar">
              <div class="rules-filter-row">
                <span class="rules-toolbar-label">筛选</span>
                <div class="chip-row rules-filter-chips">
                  <button type="button" class="chip-btn" :class="{ on: rulesFilter === 'all' }" @click="rulesFilter = 'all'">全部</button>
                  <button type="button" class="chip-btn" :class="{ on: rulesFilter === 'sensor' }" @click="rulesFilter = 'sensor'">内置传感器</button>
                  <button type="button" class="chip-btn" :class="{ on: rulesFilter === 'custom' }" @click="rulesFilter = 'custom'">快照规则</button>
                  <button type="button" class="chip-btn" :class="{ on: rulesFilter === 'elastic' }" @click="rulesFilter = 'elastic'">Elastic</button>
                </div>
              </div>
              <div v-if="isAdmin" class="rules-bulk-bar">
                <div class="rules-bulk-card">
                  <span class="rules-bulk-card-hd">当前筛选</span>
                  <div class="rules-bulk-pair">
                    <button type="button" class="rbb on" :disabled="rulesBulkBusy || !filteredAgentRules.length" @click="bulkRulesEnabled(true)">
                      {{ rulesBulkBusy ? '…' : '全部开启' }}
                    </button>
                    <button type="button" class="rbb off" :disabled="rulesBulkBusy || !filteredAgentRules.length" @click="bulkRulesEnabled(false)">
                      全部关闭
                    </button>
                  </div>
                </div>
                <div class="rules-bulk-card elastic">
                  <span class="rules-bulk-card-hd">Elastic</span>
                  <div class="rules-bulk-actions">
                    <div class="rules-bulk-pair" title="Elastic 快照规则">
                      <em>快照</em>
                      <button type="button" class="rbb on" :disabled="rulesBulkBusy" @click="bulkElasticRules(true)">开</button>
                      <button type="button" class="rbb off" :disabled="rulesBulkBusy" @click="bulkElasticRules(false)">关</button>
                    </div>
                    <div class="rules-bulk-pair" title="Elastic EVM 规则">
                      <em>EVM</em>
                      <button type="button" class="rbb on" :disabled="rulesBulkBusy" @click="bulkElasticEvm(true)">开</button>
                      <button type="button" class="rbb off" :disabled="rulesBulkBusy" @click="bulkElasticEvm(false)">关</button>
                    </div>
                  </div>
                </div>
              </div>
              <p v-else class="hint sm rules-bulk-hint">批量开启/关闭需管理员账号；单条规则可用左侧「启用」开关（若账号有权限）。</p>
            </div>
            <div class="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>启用</th>
                    <th>标题</th>
                    <th>来源</th>
                    <th>级别</th>
                    <th>类型 / 关键字</th>
                    <th>说明</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="r in filteredAgentRules"
                    :key="r.id"
                    class="row-click"
                    :class="{ active: editingRule?.id === r.id && !ruleCreating }"
                    @click="startEditRule(r)"
                  >
                    <td @click.stop>
                      <label class="switch">
                        <input type="checkbox" :checked="r.enabled" @change="toggleRule(r, $event.target.checked)" />
                        <i />
                      </label>
                    </td>
                    <td>
                      <b class="strong">{{ r.title }}</b>
                      <div class="meta">{{ r.id }}</div>
                    </td>
                    <td>
                      <span v-if="r.builtin || r.source === 'sensor'" class="pill on">内置传感器</span>
                      <span v-else-if="isElasticRule(r)" class="pill on accent">
                        {{ r.rule_channel === 'evm' || /\.(evm|fim)$/i.test(String(r.id || '')) ? 'Elastic EVM' : 'Elastic 快照' }}
                      </span>
                      <span v-else class="pill">快照规则</span>
                    </td>
                    <td><span class="sev" :data-s="r.severity">{{ sevLabel(r.severity) }}</span></td>
                    <td class="muted">
                      <template v-if="r.builtin || r.source === 'sensor'">
                        <div>{{ r.etype || 'timeline' }}</div>
                        <div v-if="r.summary_contains" class="meta">关键字：{{ r.summary_contains }}</div>
                      </template>
                      <template v-else-if="isElasticRule(r) && (r.rule_channel === 'evm' || r.etype)">
                        <div>{{ r.etype || 'timeline' }}</div>
                        <div v-if="(r.patterns || []).length" class="meta">{{ (r.patterns || []).slice(0, 2).join(' / ') }}{{ (r.patterns || []).length > 2 ? '…' : '' }}</div>
                      </template>
                      <template v-else>
                        <div>{{ (r.modules || []).map(modLabel).join('、') || '—' }}</div>
                        <div v-if="(r.patterns || []).length" class="meta">{{ (r.patterns || []).slice(0, 2).join(' / ') }}{{ (r.patterns || []).length > 2 ? '…' : '' }}</div>
                      </template>
                    </td>
                    <td class="muted" :title="r.note">{{ r.note || '—' }}</td>
                    <td class="ops" @click.stop>
                      <button type="button" class="link" @click="startEditRule(r)">编辑</button>
                      <button
                        v-if="!(r.builtin || r.source === 'sensor')"
                        type="button"
                        class="link danger"
                        @click="removeRule(r)"
                      >删除</button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-if="!filteredAgentRules.length" class="empty">当前筛选下无规则</p>
            </div>
          </div>

          <aside class="panel pad rule-editor">
            <h3>{{ ruleCreating ? '新增规则' : (editingRule ? ((editingRule.builtin || editingRule.source === 'sensor') ? '编辑内置传感器' : (isEditingElastic ? 'Elastic 规则' : '编辑规则')) : '规则编辑') }}</h3>
            <p v-if="!ruleCreating && !editingRule" class="hint">选中左侧规则编辑，或点击「新增规则」。下方可选快速模板一键填充。</p>
            <template v-if="ruleCreating || editingRule">
              <p v-if="isEditingElastic" class="hint warn">
                本端为从 Elastic 官方 query 抽取的<strong>子串近似</strong>，不是 Stack 上完整的 EQL/KQL（无 AND/序列/索引条件）。
                误报多时可先关闭「Elastic 快照」、仅保留 EVM，或到 Elasticsearch 引擎跑完整规则。
              </p>
              <div v-if="isEditingElastic" class="form-lab">
                <span>Elastic 官方 query（只读）</span>
                <p v-if="elasticOfficialBusy" class="muted">加载官方规则…</p>
                <template v-else-if="elasticOfficialDetail?.ok">
                  <p class="meta mono">{{ elasticOfficialDetail.rel_path }} · {{ elasticOfficialDetail.language || elasticOfficialDetail.type }}</p>
                  <textarea class="field area mono" rows="8" readonly :value="elasticOfficialDetail.query || '（无 query 字段）'" />
                  <p class="hint">{{ elasticOfficialDetail.official_note }}</p>
                </template>
                <p v-else class="muted">{{ elasticOfficialDetail?.error || '未加载官方 query' }}</p>
              </div>
              <p v-if="isEditingSensor" class="hint">
                与快照规则共用匹配字段、文件类型、签名、路径、关键字和匹配方式。
                数据源固定为时间线传感器，规则 ID 不可改、不可删；可恢复默认。
              </p>
              <div v-if="ruleCreating" class="form-lab">
                <span>快速模板</span>
                <div class="chip-row">
                  <button
                    v-for="t in RULE_TEMPLATES"
                    :key="t.id"
                    type="button"
                    class="chip-btn"
                    @click="applyRuleTemplate(t)"
                  >{{ t.label }}</button>
                </div>
              </div>
              <label v-if="isEditingSensor" class="form-lab">
                <span>规则 ID</span>
                <input class="field mono" :value="editingRule.id" disabled />
              </label>
              <label class="form-lab">
                <span>标题 *</span>
                <input v-model="ruleForm.title" class="field" placeholder="例如：PowerShell 编码执行" />
              </label>
              <label class="form-lab">
                <span>严重级别</span>
                <select v-model="ruleForm.severity" class="field">
                  <option value="critical">严重</option>
                  <option value="high">高危</option>
                  <option value="medium">中危</option>
                  <option value="low">低危</option>
                  <option value="info">信息</option>
                </select>
              </label>
              <template v-if="isEditingSensor || isEditingEvmOnly">
                <label class="form-lab">
                  <span>事件类型 (etype)</span>
                  <input v-model="ruleForm.etype" class="field" :disabled="isEditingEvmOnly" placeholder="如 file_create / process_create_etw" />
                </label>
              </template>
              <div v-if="!isEditingEvmOnly" class="form-lab">
                <span>{{ isEditingSensor ? '数据源' : '适用模块 *（可多选）' }}</span>
                <div v-if="isEditingSensor" class="sensor-source">
                  <span class="pill on">时间线传感器</span>
                  <small>由事件类型 etype 决定采集通道</small>
                </div>
                <div class="mod-pills">
                  <button
                    v-if="!isEditingSensor"
                    v-for="m in Object.keys(LABELS)"
                    :key="m"
                    type="button"
                    class="mod-pill"
                    :class="{ on: ruleForm.modules.includes(m) }"
                    @click="toggleRuleModule(m)"
                  >{{ LABELS[m] }}</button>
                </div>
              </div>
              <div class="form-lab">
                <span>文件类型（可选，限制扩展名；空=不限）</span>
                <div class="chip-row">
                  <button
                    v-for="ext in FILE_EXT_OPTIONS"
                    :key="ext"
                    type="button"
                    class="chip-btn"
                    :class="{ on: ruleForm.fileExts.includes(ext) }"
                    @click="toggleFileExt(ext)"
                  >.{{ ext }}</button>
                </div>
                <input
                  v-model="ruleForm.fileExtsText"
                  class="field"
                  style="margin-top:8px"
                  placeholder="也可手写：exe,dll,ps1"
                  @change="syncFileExtsFromText"
                />
              </div>
              <label class="form-lab">
                <span>签名条件</span>
                <select v-model="ruleForm.signedFilter" class="field">
                  <option value="">不限</option>
                  <option value="unsigned">仅未签名 / 签名异常</option>
                  <option value="signed">仅有效签名</option>
                </select>
              </label>
              <label class="form-lab">
                <span>路径前缀（可选，逗号分隔）</span>
                <input v-model="ruleForm.pathPrefixesText" class="field" placeholder="例如 C:\ 或 C:\Users\ 限制命中范围" />
                <p class="hint" style="margin:6px 0 0">
                  盘符根投放：regex
                  <code class="mono">^[A-Za-z]:\\[^\\]+\.(exe|dll|…)$</code>，模块 file+process。
                  ProgramData/Temp 未签名：路径前缀
                  <code class="mono">C:\ProgramData,C:\Windows\Temp</code>，签名选「仅未签名」，扩展名 exe,dll,…，特征填
                  <code class="mono">*</code>（已内置规则 agent-progdata-temp-unsigned）。
                </p>
              </label>
              <div class="form-lab">
                <span>匹配字段</span>
                <div class="chip-row sm">
                  <button
                    v-for="f in suggestedFields"
                    :key="f"
                    type="button"
                    class="chip-btn"
                    :class="{ on: fieldsSet.has(f) }"
                    @click="toggleField(f)"
                  >{{ COL_LABELS[f] || f }}</button>
                </div>
                <input v-model="ruleForm.fieldsText" class="field" style="margin-top:8px" placeholder="path,command_line,name" />
              </div>
              <label class="form-lab">
                <span>匹配特征 *（每行一条）</span>
                <textarea v-model="ruleForm.patternsText" class="field area" rows="5" placeholder="-enc &#10;\\temp\\" />
              </label>
              <label class="form-lab">
                <span>匹配方式</span>
                <select v-model="ruleForm.match" class="field">
                  <option value="substring">包含（推荐）</option>
                  <option value="regex">正则</option>
                  <option value="exact">精确</option>
                </select>
              </label>
              <label class="form-lab">
                <span>备注</span>
                <input v-model="ruleForm.note" class="field" placeholder="可选说明" />
              </label>
              <label class="chk">
                <input type="checkbox" v-model="ruleForm.enabled" />
                启用此规则
              </label>
              <p v-if="ruleFormError" class="err-text">{{ ruleFormError }}</p>
              <div class="row" style="margin-top:14px">
                <button
                  v-if="!isEditingEvmOnly"
                  type="button"
                  class="btn primary"
                  :disabled="ruleSaving"
                  @click="saveRuleForm"
                >
                  {{ ruleSaving ? '保存中…' : '保存' }}
                </button>
                <p v-else class="hint">EVM 规则在 <code class="mono">elastic_evm_import.json</code> 中维护；此处仅查看与开关。</p>
                <button
                  v-if="isEditingSensor"
                  type="button"
                  class="btn"
                  :disabled="ruleSaving"
                  @click="resetSensorRule"
                >恢复默认</button>
                <button type="button" class="btn" @click="cancelRuleForm">取消</button>
              </div>
            </template>
          </aside>
        </div>

        <div v-show="rulesSection === 'whitelist'" class="rules-layout wl-layout">
          <div class="panel fill pad">
            <h3 style="margin:0 0 4px">告警加白（抑制规则）</h3>
            <p class="muted" style="margin:0 0 12px;font-size:13px">
              与检出规则不同：加白后<strong>不再产生同类告警</strong>（所有检测来源、含 Elastic/传感器/ES EQL 均生效）。
              终端通过 sync 的 <code class="mono">whitelist</code> 块同步。也可在威胁事件里点「加白」快速创建。
            </p>
            <div v-if="isAdmin" class="hunt-bar" style="margin-bottom:12px">
              <select v-model="wlKind" class="search sev-filter">
                <option v-for="(lb, k) in ALLOW_KIND_LABELS" :key="k" :value="k">{{ lb }}</option>
              </select>
              <input v-model="wlValue" class="search grow" placeholder="匹配值，如 C:\Tools\*.exe" />
              <input v-model="wlRule" class="search" style="max-width:200px" placeholder="限定告警标题（可选 *）" />
              <input v-model="wlNote" class="search" style="max-width:160px" placeholder="备注" />
              <button type="button" class="btn primary" @click="addWl">添加</button>
            </div>
            <div class="chip-row" style="padding:0 0 10px">
              <input v-model="wlSearch" class="search grow" placeholder="搜索值 / 备注 / 标题限定…" style="max-width:320px" />
              <button type="button" class="chip-btn" :class="{ on: wlListFilter === 'all' }" @click="wlListFilter = 'all'">全部</button>
              <button type="button" class="chip-btn" :class="{ on: wlListFilter === 'enabled' }" @click="wlListFilter = 'enabled'">启用中</button>
              <button type="button" class="chip-btn" :class="{ on: wlListFilter === 'disabled' }" @click="wlListFilter = 'disabled'">已停用</button>
            </div>
            <div class="table-scroll">
              <table v-if="filteredWhitelist.length">
                <thead>
                  <tr>
                    <th>类型</th><th>值</th><th>限定告警</th><th>范围</th><th>命中</th><th>最近命中</th><th>备注</th><th>状态</th><th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="w in filteredWhitelist" :key="w.id" :class="{ 'wl-off': !w.enabled }">
                    <td>{{ ALLOW_KIND_LABELS[w.kind] || w.kind }}</td>
                    <td class="mono wl-val" :title="w.value">{{ w.value }}</td>
                    <td class="wl-val" :title="w.rule">{{ w.rule || '全部' }}</td>
                    <td>{{ w.agent_id ? agentLabel(w.agent_id) : '全部终端' }}</td>
                    <td>{{ w.hits || 0 }}</td>
                    <td>{{ w.last_hit_at ? fmtTime(w.last_hit_at) : '—' }}</td>
                    <td>{{ w.note || '—' }}</td>
                    <td>
                      <button v-if="isAdmin" type="button" class="btn-text" @click="toggleWl(w)">{{ w.enabled ? '启用中' : '已停用' }}</button>
                      <span v-else>{{ w.enabled ? '启用' : '停用' }}</span>
                    </td>
                    <td>
                      <button v-if="isAdmin" type="button" class="btn-text" style="color:var(--danger)" @click="delWl(w.id)">删除</button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-else class="empty sm">暂无加白条目（或当前筛选无结果）</p>
            </div>
          </div>
          <aside class="panel pad wl-side">
            <h3 style="margin:0 0 10px">加白如何生效</h3>
            <ul class="wl-help">
              <li>保存后写入平台库，并通过 Agent <strong>sync</strong> 下发 <code class="mono">whitelist</code> 块。</li>
              <li>命中加白的进程名 / 路径 / 哈希 / 注册表等，<strong>不再重复告警</strong>（含 Elastic、传感器、EVM）。</li>
              <li>「限定告警标题」可填 <code class="mono">*</code> 或关键词，避免一条加白误伤其它规则。</li>
              <li>「范围」留空 = 全部终端；也可在威胁详情里对单台加白。</li>
            </ul>
            <h4 style="margin:16px 0 8px">类型说明</h4>
            <dl class="wl-kind-dl">
              <div v-for="(lb, k) in ALLOW_KIND_LABELS" :key="'wlh-'+k">
                <dt>{{ lb }}</dt>
                <dd>{{ wlKindHint(k) }}</dd>
              </div>
            </dl>
            <p class="hint sm" style="margin-top:14px">当前 {{ whitelistEnabledCount }}/{{ whitelist.length }} 条启用 · 命中次数在列表中可审计。</p>
          </aside>
        </div>

        <div v-show="rulesSection === 'memory'" class="mem-yara-layout">
          <p v-if="memoryYaraErr" class="err-text">{{ memoryYaraErr }}</p>
          <p v-if="memoryYaraErr" class="hint sm">
            规则目录：<code class="mono">agent/memory-yara/</code> · 点「刷新规则包」重试。
          </p>

          <template v-else-if="memoryYaraPack?.ok">
            <div class="mem-yara-top">
              <div class="mem-yara-stats">
                <div class="mem-yara-stat">
                  <label>包版本</label>
                  <b class="mono" :title="memoryYaraPack.rev">{{ shortHash(memoryYaraPack.rev || memoryYaraPack.manifest?.version || '—') }}</b>
                </div>
                <button type="button" class="mem-yara-stat click" :class="{ on: memoryYaraView === 'strings' }" @click="memoryYaraView = 'strings'">
                  <label>字符串规则</label>
                  <b>{{ memoryYaraPack.rule_count ?? 0 }}/{{ memoryYaraPack.rule_count_total ?? (memoryYaraPack.items || []).length }}</b>
                </button>
                <button type="button" class="mem-yara-stat click accent" :class="{ on: memoryYaraView === 'yar' }" @click="memoryYaraView = 'yar'">
                  <label>YARA 文件</label>
                  <b>{{ memoryYaraPack.yar_active ?? 0 }}/{{ memoryYaraPack.yar_total || (memoryYaraPack.yar_files_all || []).length || 0 }}</b>
                </button>
                <button type="button" class="mem-yara-stat click" :class="{ on: memoryYaraView === 'meta' }" @click="memoryYaraView = 'meta'">
                  <label>Valhalla</label>
                  <b>{{ memoryYaraPack.valhalla?.present ? ('≈ ' + (memoryYaraPack.valhalla.rule_count || '?')) : '—' }}</b>
                </button>
              </div>
              <div class="mem-yara-toggles" v-if="memoryYaraPack.controls">
                <div
                  v-for="gk in MEMORY_YARA_GROUP_KEYS"
                  :key="'myg-'+gk"
                  class="mem-yara-tog"
                  :class="{ off: memoryYaraPack.controls.groups?.[gk] === false }"
                >
                  <span>{{ memoryYaraPack.group_labels?.[gk] || gk }}</span>
                  <label class="switch mem-yara-switch" @click.stop>
                    <input
                      type="checkbox"
                      :disabled="!isAdmin || memoryYaraControlsBusy"
                      :checked="memoryYaraPack.controls.groups?.[gk] !== false"
                      @change="setMemoryYaraGroup(gk, $event.target.checked)"
                    />
                    <i aria-hidden="true" />
                  </label>
                </div>
              </div>
            </div>

            <nav class="mem-yara-subnav">
              <button type="button" :class="{ on: memoryYaraView === 'strings' }" @click="memoryYaraView = 'strings'">
                字符串规则 <em>{{ (memoryYaraPack.items || []).length }}</em>
              </button>
              <button type="button" :class="{ on: memoryYaraView === 'yar' }" @click="memoryYaraView = 'yar'">
                YARA 文件 <em>{{ memoryYaraPack.yar_total || (memoryYaraPack.yar_files_all || []).length || 0 }}</em>
              </button>
              <button type="button" :class="{ on: memoryYaraView === 'meta' }" @click="memoryYaraView = 'meta'">包信息</button>
            </nav>

            <div v-show="memoryYaraView === 'strings'" class="mem-yara-body" :class="{ dim: memoryYaraPack.controls?.groups?.string_rules === false }">
              <div class="mem-yara-toolbar">
                <div>
                  <h3>rules.json 轻量字符串</h3>
                  <p>不编译 YARA 也能扫；全量签名在「YARA 文件」。Sync 下发，改完下次同步生效。</p>
                </div>
                <div class="mem-yara-toolbar-actions" v-if="isAdmin">
                  <button type="button" class="btn sm" :disabled="memoryYaraControlsBusy || memoryYaraPack.controls?.groups?.string_rules === false" @click="setAllMemoryYaraStringRules(true)">全部启用</button>
                  <button type="button" class="btn sm" :disabled="memoryYaraControlsBusy || memoryYaraPack.controls?.groups?.string_rules === false" @click="setAllMemoryYaraStringRules(false)">全部关闭</button>
                </div>
              </div>
              <p v-if="memoryYaraPack.controls?.groups?.string_rules === false" class="mem-yara-banner">本组总开关已关，单条不可改，Agent 不下发字符串规则。</p>
              <div class="mem-yara-scroll">
                <table class="mem-yara-table">
                  <colgroup>
                    <col v-if="isAdmin" style="width:64px" />
                    <col style="width:22%" />
                    <col style="width:22%" />
                    <col style="width:72px" />
                    <col style="width:16%" />
                    <col />
                  </colgroup>
                  <thead>
                    <tr>
                      <th v-if="isAdmin">启用</th>
                      <th>ID</th>
                      <th>标题</th>
                      <th>级别</th>
                      <th>MITRE</th>
                      <th>匹配串</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="r in memoryYaraPack.items || []" :key="r.id" :class="{ 'row-off': r.enabled === false }">
                      <td v-if="isAdmin">
                        <label class="switch mem-yara-switch">
                          <input
                            type="checkbox"
                            :disabled="memoryYaraControlsBusy || memoryYaraPack.controls?.groups?.string_rules === false"
                            :checked="r.enabled !== false"
                            @change="toggleMemoryYaraStringRule(r, $event.target.checked)"
                          />
                          <i aria-hidden="true" />
                        </label>
                      </td>
                      <td class="mono">{{ r.id }}</td>
                      <td><b>{{ r.title }}</b></td>
                      <td><span class="sev" :data-s="r.severity">{{ sevLabel(r.severity) }}</span></td>
                      <td class="mono muted">{{ (r.mitre || []).join(', ') || '—' }}</td>
                      <td class="mono muted mem-yara-str" :title="(r.strings || []).join(' | ')">
                        {{ ((r.strings || []).slice(0, 3).join(' · ')) || '—' }}{{ (r.strings || []).length > 3 ? '…' : '' }}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div v-show="memoryYaraView === 'yar'" class="mem-yara-body">
              <div class="mem-yara-toolbar">
                <div>
                  <h3>YARA 规则文件</h3>
                  <p><code class="mono">agent/memory-yara/</code> · ep_*.yar（Hacktool/勒索/Trojan）+ 内置 .yar。分组开关在上方。</p>
                </div>
                <span class="meta">{{ memoryYaraPack.yar_active ?? 0 }} / {{ memoryYaraPack.yar_total || 0 }} 启用</span>
              </div>
              <div class="mem-yara-scroll">
                <table class="mem-yara-table">
                  <colgroup>
                    <col style="width:72px" />
                    <col />
                    <col style="width:240px" />
                  </colgroup>
                  <thead>
                    <tr><th>状态</th><th>文件</th><th>分组</th></tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="f in (memoryYaraPack.yar_files_all || []).length ? memoryYaraPack.yar_files_all : (memoryYaraPack.yar_files || []).map((n) => ({ name: n, enabled: true, group: 'protections_yara' }))"
                      :key="f.name || f"
                      :class="{ 'row-off': f.enabled === false }"
                    >
                      <td><span class="pill sm" :class="f.enabled === false ? '' : 'on'">{{ f.enabled === false ? '关闭' : '启用' }}</span></td>
                      <td class="mono">{{ f.name || f }}</td>
                      <td class="muted">{{ memoryYaraPack.group_labels?.[f.group] || f.group || '—' }}</td>
                    </tr>
                    <tr v-if="!(memoryYaraPack.yar_files_all || []).length && !(memoryYaraPack.yar_files || []).length">
                      <td colspan="3" class="muted">未发现 .yar 文件</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <div v-show="memoryYaraView === 'meta'" class="mem-yara-body meta">
              <div class="mem-yara-meta-grid">
                <section>
                  <h4>轻量包</h4>
                  <dl>
                    <div><dt>名称</dt><dd>{{ memoryYaraPack.manifest?.name || '—' }}</dd></div>
                    <div><dt>版本</dt><dd class="mono">{{ memoryYaraPack.manifest?.version || memoryYaraPack.rev || '—' }}</dd></div>
                    <div v-if="memoryYaraPack.manifest?.updated_at"><dt>更新</dt><dd>{{ memoryYaraPack.manifest.updated_at }}</dd></div>
                    <div v-if="memoryYaraPack.sha256"><dt>SHA256</dt><dd class="mono" :title="memoryYaraPack.sha256">{{ shortHash(memoryYaraPack.sha256) }}</dd></div>
                    <div class="full" v-if="memoryYaraPack.manifest?.description"><dt>说明</dt><dd>{{ memoryYaraPack.manifest.description }}</dd></div>
                  </dl>
                </section>
                <section v-if="memoryYaraPack.valhalla?.present">
                  <h4>Valhalla 主库 <span class="pill sm" :class="{ on: memoryYaraPack.valhalla_included_in_agent_bundle }">{{ memoryYaraPack.valhalla_included_in_agent_bundle ? '已编入包' : '未编入包' }}</span></h4>
                  <dl>
                    <div><dt>路径</dt><dd class="mono">{{ memoryYaraPack.valhalla.path }}</dd></div>
                    <div><dt>大小</dt><dd>{{ fmtSize(memoryYaraPack.valhalla.size) }}</dd></div>
                    <div v-if="memoryYaraPack.valhalla.retrieved"><dt>检索</dt><dd>{{ memoryYaraPack.valhalla.retrieved }}</dd></div>
                    <div class="full"><dt>说明</dt><dd>{{ memoryYaraPack.valhalla.note }}</dd></div>
                  </dl>
                </section>
                <section>
                  <h4>仓库路径</h4>
                  <dl>
                    <div><dt>主库</dt><dd class="mono">{{ memoryYaraPack.repo_paths?.yara_corpus || 'yara/' }}</dd></div>
                    <div><dt>轻量包</dt><dd class="mono">{{ memoryYaraPack.repo_paths?.agent_memory_pack || 'agent/memory-yara/' }}</dd></div>
                    <div class="full" v-if="memoryYaraPack.sigma_note"><dt>注意</dt><dd>{{ memoryYaraPack.sigma_note }}</dd></div>
                  </dl>
                </section>
              </div>
            </div>
          </template>
          <p v-else-if="!memoryYaraBusy" class="empty">暂无规则包数据，点右上角「刷新规则包」</p>
        </div>
      </section>

      <!-- ========== AI 分析 ========== -->
      <section v-else-if="page === 'ai-analyze'" class="page ai-page">
        <header class="page-hd">
          <div>
            <h1>AI 分析</h1>
            <p class="desc">Agentic SOC 风格 · Team Leader 调度多 Agent · 感知—调查—研判—处置建议（人工审核）</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn sm" :disabled="aiHostsLoading" @click="loadAiAnalyzePage({ force: true })">
              {{ aiHostsLoading ? '刷新中…' : '刷新终端' }}
            </button>
            <button
              v-if="isAdmin"
              type="button"
              class="btn sm primary"
              :disabled="aiBusy"
              @click="setupLocalAiModel()"
            >同步本地模型</button>
          </div>
        </header>

        <div class="ai-status-bar panel pad">
          <div class="ai-status-main">
            <span class="pill" :class="aiStatusInfo.configured ? 'ok' : 'warn'">
              {{ aiStatusInfo.configured ? '模型已就绪' : '模型未配置' }}
            </span>
            <span class="mono muted">{{ aiStatusInfo.base_url || '—' }}</span>
            <span class="mono">{{ aiStatusInfo.model || '—' }}</span>
            <span class="muted">来源 {{ aiStatusInfo.source || '—' }} · 超时 {{ aiStatusInfo.timeout || 120 }}s</span>
          </div>
          <div class="ai-status-skills muted">
            Skill 根目录：<code class="mono">{{ aiStatusInfo.skills_root || 'skills' }}</code>
            · 库内索引 {{ aiStatusInfo.skills_total || aiSkillsMeta.total_indexed || '—' }}
            · EDR 相关 {{ aiStatusInfo.skills_edr || aiSkillsMeta.edr_relevant || aiSkills.length }}
            · 列表展示 {{ aiSkills.length }}
          </div>
        </div>

        <div class="ai-layout">
          <aside class="ai-host-pane panel">
            <div class="panel-hd">
              <h3>在线终端 <em>{{ aiOnlineHosts.length }}</em></h3>
              <label class="ai-only-online">
                <input type="checkbox" v-model="aiOnlyOnline" /> 仅在线
                <span v-if="aiHostsLoading" class="muted sm">同步中</span>
              </label>
            </div>
            <div class="ai-host-list">
              <button
                v-for="h in aiVisibleHosts"
                :key="h.agent_id"
                type="button"
                class="ai-host-row"
                :class="{ on: aiSelectedId === h.agent_id, offline: !h.online }"
                :disabled="aiBusy && aiSelectedId === h.agent_id"
                @click="runAiAnalyze(h)"
              >
                <span class="ai-host-dot" :class="{ on: h.online }" />
                <span class="ai-host-meta">
                  <b>{{ h.hostname || h.agent_id }}</b>
                  <small class="mono">{{ h.ip || h.last_ip || '—' }} · {{ h.online ? '在线' : '离线' }}</small>
                </span>
                <span class="ai-host-badges">
                  <em v-if="h.open_threat_count" class="pill danger">威胁 {{ h.open_threat_count }}</em>
                  <em v-else-if="h.threat_count" class="pill soft">历史 {{ h.threat_count }}</em>
                </span>
              </button>
              <p v-if="!aiVisibleHosts.length && aiHostsLoading" class="empty sm">正在拉取在线终端…</p>
              <p v-else-if="!aiVisibleHosts.length" class="empty sm">暂无终端，请先部署 Agent 或点「刷新终端」</p>
            </div>
          </aside>

          <main class="ai-result-pane panel">
            <div class="panel-hd">
              <h3>
                研判结果
                <template v-if="aiSelectedHost"> · {{ aiSelectedHost.hostname || aiSelectedHost.agent_id }}</template>
              </h3>
              <span v-if="aiRefining" class="pill warn">模型精炼中…</span>
              <span v-else-if="aiResult" class="muted">{{ aiResult.mode }} · {{ aiResult.elapsed_ms || 0 }} ms</span>
            </div>

            <div v-if="aiBusy && !aiResult" class="ai-busy">
              <div class="ai-spinner" />
              <p>正在快速汇总快照 / 威胁事件 / 日志…</p>
              <p class="muted sm">约 1 秒内先出启发式结论，随后自动精炼。</p>
            </div>

            <div v-else-if="aiErrorText" class="ai-empty">
              <p class="hint warn">分析失败：{{ aiErrorText }}</p>
              <p class="muted">可再次点击左侧终端重试；若模型超时，仍会尽量返回启发式结论。</p>
            </div>

            <div v-else-if="aiResult" class="ai-result-body">
              <div class="ai-hero">
                <div class="ai-hero-verdict">
                  <span class="ai-verdict" :data-v="aiResult.result?.verdict || ''">{{ aiResult.result?.verdict || '待研判' }}</span>
                  <div class="ai-hero-meta">
                    <b :class="'sev-' + String(aiResult.result?.risk_level || '').toLowerCase()">
                      {{ aiResult.result?.risk_level || '—' }} · {{ aiResult.result?.risk_score ?? '—' }}
                    </b>
                    <small class="mono muted">{{ aiResult.mode }} · {{ aiResult.model || 'Agent Team' }} · {{ aiResult.elapsed_ms || 0 }} ms</small>
                  </div>
                </div>
                <div class="ai-hero-stats">
                  <button type="button" class="ai-hero-stat" @click="aiTab = 'threats'">
                    <label>威胁</label>
                    <b>{{ (aiResult.result?.threat_events || []).length || aiResult.pack_stats?.threat_events || 0 }}</b>
                  </button>
                  <button type="button" class="ai-hero-stat" @click="aiTab = 'logs'">
                    <label>日志 / 规则</label>
                    <b>{{ aiResult.pack_stats?.security_logs || 0 }} / {{ aiResult.pack_stats?.log_rule_hits || 0 }}</b>
                  </button>
                  <button type="button" class="ai-hero-stat" @click="aiTab = 'entity'">
                    <label>实体</label>
                    <b>{{ (aiResult.result?.entities || []).length }}</b>
                  </button>
                  <button type="button" class="ai-hero-stat" @click="aiTab = 'resp'">
                    <label>处置建议</label>
                    <b>{{ (aiResult.result?.dispositions || []).length }}</b>
                  </button>
                </div>
              </div>

              <p class="ai-scope-banner" v-if="aiResult.result?.data_scope">
                <b>分析范围</b>
                <span>{{ aiResult.result.data_scope.note }}</span>
                <em class="muted">
                  快照 {{ (aiResult.result.data_scope.snapshots || []).length }} 类 ·
                  威胁 {{ aiResult.result.data_scope.threat_events || 0 }} ·
                  时间线 {{ aiResult.result.data_scope.timeline || 0 }} ·
                  调查日志 {{ aiResult.result.data_scope.investigate_logs || 0 }} ·
                  规则命中 {{ aiResult.result.data_scope.log_rule_hits || 0 }}
                </em>
              </p>

              <nav class="ai-tabs">
                <button type="button" :class="{ on: aiTab === 'overview' }" @click="aiTab = 'overview'">概览</button>
                <button type="button" :class="{ on: aiTab === 'chain' }" @click="aiTab = 'chain'">
                  攻击链路
                  <em v-if="aiResult.result?.attack_graph?.stage_count">{{ aiResult.result.attack_graph.stage_count }}</em>
                </button>
                <button type="button" :class="{ on: aiTab === 'threats' }" @click="aiTab = 'threats'">
                  AI 研判事件
                  <em v-if="(aiResult.result?.threat_events || []).length">{{ (aiResult.result.threat_events || []).length }}</em>
                </button>
                <button type="button" :class="{ on: aiTab === 'think' }" @click="aiTab = 'think'">
                  AI 思维链
                  <em v-if="(aiResult.result?.thinking_chain || []).length">{{ (aiResult.result.thinking_chain || []).length }}</em>
                </button>
                <button type="button" :class="{ on: aiTab === 'logs' }" @click="aiTab = 'logs'">
                  日志取证
                  <em v-if="(aiResult.result?.forensics_logs || aiResult.result?.security_logs || []).length">
                    {{ (aiResult.result?.forensics_logs || aiResult.result?.security_logs || []).length }}
                  </em>
                </button>
                <button type="button" :class="{ on: aiTab === 'entity' }" @click="aiTab = 'entity'">实体</button>
                <button type="button" :class="{ on: aiTab === 'report' }" @click="aiTab = 'report'">报告</button>
                <button type="button" :class="{ on: aiTab === 'resp' }" @click="aiTab = 'resp'">处置</button>
              </nav>

              <div v-show="aiTab === 'overview'" class="ai-tab-pane ai-overview">
                <div v-if="(aiResult.result?.team?.agents || []).length" class="ai-team-strip">
                  <div
                    v-for="a in aiResult.result.team.agents"
                    :key="a.id"
                    class="ai-team-pill"
                    :title="a.summary"
                  >
                    <i />
                    <span>
                      <b>{{ a.name }}</b>
                      <small>{{ a.role }}</small>
                    </span>
                    <em>{{ a.status === 'done' ? '完成' : a.status }}</em>
                  </div>
                </div>

                <div class="ai-board">
                  <section class="ai-board-main">
                    <div class="ai-panel">
                      <header class="ai-panel-hd">
                        <h4>AI 研判事件</h4>
                        <button type="button" class="btn-text sm" @click="aiTab = 'threats'">全部 →</button>
                      </header>
                      <div v-if="(aiResult.result?.threat_events || []).length" class="ai-threat-preview">
                        <button
                          v-for="(ev, i) in (aiResult.result.threat_events || []).slice(0, 6)"
                          :key="ev.id || i"
                          type="button"
                          class="ai-threat-row"
                          @click="aiThreatIdx = i; aiTab = 'threats'"
                        >
                          <span class="pill" :data-ai="ev.ai?.conclusion || ''">{{ ev.ai?.conclusion || '待研判' }}</span>
                          <span class="ai-threat-row-body">
                            <b>{{ ev.title || '未命名告警' }}</b>
                            <small>{{ (ev.ai?.reasoning && ev.ai.reasoning[0]) || ev.ai?.note || '—' }}</small>
                          </span>
                          <em class="muted sm">{{ ev.ai?.confidence != null ? ev.ai.confidence + '%' : '' }}</em>
                        </button>
                      </div>
                      <p v-else class="ai-panel-empty">暂无 AI 研判事件</p>
                    </div>

                    <div class="ai-panel">
                      <header class="ai-panel-hd">
                        <h4>攻击时间线</h4>
                        <span class="muted sm">威胁 + 安全日志</span>
                      </header>
                      <ol v-if="(aiResult.result?.attack_timeline || []).length" class="ai-rail">
                        <li v-for="(t, i) in aiResult.result.attack_timeline.slice(0, 10)" :key="i">
                          <span class="ai-rail-dot" :data-k="t.kind || ''" />
                          <div>
                            <div class="ai-rail-top">
                              <time>{{ t.ts || '—' }}</time>
                              <span class="pill soft">{{ t.kind }}</span>
                            </div>
                            <b>{{ t.title }}</b>
                            <small v-if="t.detail">{{ t.detail }}</small>
                          </div>
                        </li>
                      </ol>
                      <p v-else class="ai-panel-empty">暂无攻击时间线节点</p>
                    </div>
                  </section>

                  <aside class="ai-board-side">
                    <div class="ai-panel">
                      <header class="ai-panel-hd"><h4>调查流水线</h4></header>
                      <ol v-if="(aiResult.result?.pipeline || []).length" class="ai-steps">
                        <li v-for="(p, i) in aiResult.result.pipeline" :key="i">
                          <span class="ai-step-no">{{ i + 1 }}</span>
                          <div>
                            <b>{{ p.stage }}</b>
                            <span>{{ p.goal }}</span>
                            <small v-if="typeof p.output === 'string'">{{ p.output }}</small>
                            <small v-else-if="p.output?.what">{{ p.output.what }}</small>
                            <em v-if="(p.deliverables || []).length">{{ (p.deliverables || []).join(' · ') }}</em>
                          </div>
                        </li>
                      </ol>
                      <p v-else class="ai-panel-empty">暂无流水线</p>
                    </div>

                    <div v-if="aiResult.result?.alert_meta" class="ai-panel">
                      <header class="ai-panel-hd"><h4>告警基本信息</h4></header>
                      <dl class="ai-meta-compact">
                        <div><dt>来源</dt><dd>{{ aiResult.result.alert_meta.source || '—' }}</dd></div>
                        <div><dt>分析规则</dt><dd>{{ aiResult.result.alert_meta.analysis_rule || '—' }}</dd></div>
                        <div><dt>关联告警</dt><dd>{{ aiResult.result.alert_meta.related_alerts ?? '—' }}</dd></div>
                        <div><dt>资产</dt><dd>{{ aiResult.result.alert_meta.hostname || '—' }}</dd></div>
                        <div class="full"><dt>ATT&CK</dt><dd>{{ (aiResult.result.alert_meta.attck_stages || []).join(' · ') || '—' }}</dd></div>
                        <div class="full" v-if="aiResult.result?.root_cause"><dt>根因</dt><dd>{{ aiResult.result.root_cause }}</dd></div>
                      </dl>
                    </div>

                    <div class="ai-panel ai-quick">
                      <header class="ai-panel-hd"><h4>快捷入口</h4></header>
                      <div class="ai-quick-row">
                        <button type="button" @click="aiTab = 'think'">思维链 {{ (aiResult.result?.thinking_chain || []).length }}</button>
                        <button type="button" @click="aiTab = 'logs'">日志 {{ (aiResult.result?.security_logs || []).length }}</button>
                        <button type="button" @click="aiTab = 'report'">报告</button>
                        <button type="button" @click="aiTab = 'resp'">处置 {{ (aiResult.result?.dispositions || []).length }}</button>
                      </div>
                    </div>
                  </aside>
                </div>
              </div>

              <div v-show="aiTab === 'chain'" class="ai-tab-pane ai-chain-pane">
                <div class="ai-section-hd">
                  <div>
                    <label>攻击链路图</label>
                    <span class="muted sm">{{ aiResult.result?.attack_graph?.summary || '将主机 → 各 ATT&CK 阶段 → 证据串联' }}</span>
                  </div>
                  <button type="button" class="btn-text sm" @click="aiTab = 'logs'">日志取证 →</button>
                </div>
                <div v-if="(aiResult.result?.attack_graph?.nodes || []).length" class="ai-chain-board">
                  <div class="ai-chain-flow">
                    <template v-for="(n, i) in aiResult.result.attack_graph.nodes" :key="n.id">
                      <div
                        class="ai-chain-node"
                        :class="[n.type, { on: aiChainNodeId === n.id }]"
                        @click="aiChainNodeId = n.id"
                      >
                        <span class="ai-chain-badge">{{ n.type === 'host' ? '主机' : (i) }}</span>
                        <b>{{ n.label }}</b>
                        <small v-if="n.sub">{{ n.sub }}</small>
                        <em v-if="n.count">{{ n.count }} 证据</em>
                      </div>
                      <div
                        v-if="i < aiResult.result.attack_graph.nodes.length - 1"
                        class="ai-chain-arrow"
                        aria-hidden="true"
                      >→</div>
                    </template>
                  </div>
                  <div class="ai-chain-detail" v-if="aiChainNode">
                    <header>
                      <h4>{{ aiChainNode.label }}</h4>
                      <span class="muted sm">{{ aiChainNode.sub || aiChainNode.type }}</span>
                    </header>
                    <div v-if="(aiChainNode.items || []).length" class="ai-chain-items">
                      <article v-for="(it, ii) in aiChainNode.items" :key="ii" class="ai-chain-item" :data-k="it.kind">
                        <div class="ai-chain-item-top">
                          <span class="pill soft">{{ it.kind }}</span>
                          <time>{{ it.ts || '—' }}</time>
                        </div>
                        <b>{{ it.title }}</b>
                        <p>{{ it.detail || '—' }}</p>
                      </article>
                    </div>
                    <p v-else class="muted">该节点无挂接明细证据</p>
                    <div class="ai-threat-actions">
                      <button type="button" class="btn sm" @click="aiTab = 'threats'">看 AI 研判事件</button>
                      <button type="button" class="btn sm" @click="aiTab = 'entity'">看实体</button>
                    </div>
                  </div>
                </div>
                <div v-else class="ai-panel-empty fill">暂无线路节点。请确认 Agent 已回传威胁/日志后再分析。</div>
              </div>

              <div v-show="aiTab === 'threats'" class="ai-tab-pane">
                <div class="ai-threats-head">
                  <label>AI 研判事件（本地 Agent / 模型结论，非原始告警照搬）</label>
                  <span class="muted sm">
                    {{ (aiResult.result?.threat_events || []).length }} 条 ·
                    主机结论 {{ aiResult.result?.verdict || '—' }} ·
                    点行看推理与处置建议
                  </span>
                </div>
                <div class="ai-threats-layout">
                  <div class="ai-threats-list">
                    <table class="ai-mini-tbl">
                      <thead>
                        <tr>
                          <th>AI 结论</th>
                          <th>置信</th>
                          <th>原告警</th>
                          <th>角色</th>
                          <th>阶段</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr
                          v-for="(ev, i) in (aiResult.result?.threat_events || [])"
                          :key="ev.id || i"
                          :class="{ on: aiThreatIdx === i }"
                          @click="aiThreatIdx = i"
                        >
                          <td>
                            <span class="pill" :data-ai="ev.ai?.conclusion || ''">{{ ev.ai?.conclusion || '待研判' }}</span>
                          </td>
                          <td class="mono">{{ ev.ai?.confidence != null ? ev.ai.confidence + '%' : '—' }}</td>
                          <td :title="ev.title">
                            <b class="ai-threat-title">{{ ev.title || '未命名告警' }}</b>
                            <small class="muted">EDR {{ ev.severity || '—' }} · {{ ev.process_name || ev.path || ev.etype || '' }}</small>
                          </td>
                          <td>
                            <span class="pill soft" :data-role="ev.ai?.role || ''">{{ ev.ai?.role || '—' }}</span>
                          </td>
                          <td>{{ ev.ai?.chain_stage || '—' }}</td>
                        </tr>
                        <tr v-if="!(aiResult.result?.threat_events || []).length">
                          <td colspan="5" class="muted">暂无可供 AI 研判的威胁；请确认终端已上报告警。</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  <aside v-if="aiThreatCard" class="ai-threat-card">
                    <div class="ai-threat-card-top">
                      <span class="pill" :data-ai="aiThreatCard.ai?.conclusion || ''">{{ aiThreatCard.ai?.conclusion || '待研判' }}</span>
                      <b v-if="aiThreatCard.ai?.confidence != null">置信 {{ aiThreatCard.ai.confidence }}%</b>
                    </div>
                    <h4>{{ aiThreatCard.title || '研判详情' }}</h4>
                    <p class="muted sm">原 EDR #{{ aiThreatCard.id || '—' }} · {{ aiThreatCard.severity || '—' }} · {{ aiThreatCard.etype || '—' }}</p>
                    <div class="ai-think-block">
                      <label>AI 结论说明</label>
                      <p>{{ aiThreatCard.ai?.note || '暂无' }}</p>
                    </div>
                    <div class="ai-think-block" v-if="(aiThreatCard.ai?.reasoning || []).length">
                      <label>AI 推理过程</label>
                      <ul>
                        <li v-for="(r, ri) in aiThreatCard.ai.reasoning" :key="ri">{{ r }}</li>
                      </ul>
                    </div>
                    <div class="ai-think-block">
                      <label>处置建议</label>
                      <p>{{ aiThreatCard.ai?.recommendation || '—' }}</p>
                    </div>
                    <div class="ai-think-block" v-if="(aiThreatCard.ai?.attck || []).length">
                      <label>关联 ATT&CK</label>
                      <p>{{ (aiThreatCard.ai.attck || []).join(' · ') }}</p>
                    </div>
                    <div class="ai-think-block" v-if="(aiThreatCard.ai?.entities || []).length">
                      <label>关联实体</label>
                      <ul>
                        <li v-for="(en, ei) in aiThreatCard.ai.entities" :key="ei">
                          [{{ en.type }}/{{ en.risk }}] <code>{{ en.value }}</code>
                        </li>
                      </ul>
                    </div>
                    <div class="ai-think-block" v-if="(aiThreatCard.ai?.signals || []).length">
                      <label>命中信号</label>
                      <p>{{ (aiThreatCard.ai.signals || []).join(' · ') }}</p>
                    </div>
                    <div class="ai-think-block">
                      <label>原始证据（EDR）</label>
                      <p class="mono sm">{{ aiThreatCard.matched || aiThreatCard.summary || '—' }}</p>
                      <p v-if="aiThreatCard.command_line" class="mono sm">{{ aiThreatCard.command_line }}</p>
                    </div>
                    <div class="ai-threat-actions">
                      <button type="button" class="btn sm" @click="aiTab = 'think'">看 AI 思维链</button>
                      <button type="button" class="btn sm" @click="aiTab = 'resp'">去处置</button>
                      <button type="button" class="btn sm" @click="goMenu('events')">原始威胁事件</button>
                    </div>
                  </aside>
                </div>
              </div>

              <div v-show="aiTab === 'think'" class="ai-tab-pane">
                <div class="ai-think-banner">
                  <b>AI ReAct 思维链</b>
                  <span class="muted sm">每步含线索 / 假设 / 推理 / 观察，并挂接本机告警与日志证据；模型精炼后会追加一步。</span>
                </div>
                <div v-if="(aiResult.result?.thinking_chain || []).length" class="ai-think">
                  <div class="ai-think-layout">
                    <aside class="ai-think-steps">
                      <button
                        v-for="(s, i) in aiResult.result.thinking_chain"
                        :key="s.id || i"
                        type="button"
                        class="ai-think-step"
                        :class="{ on: aiThinkIdx === i, llm: s.phase === '模型精炼' }"
                        @click="aiThinkIdx = i"
                      >
                        <b>{{ i + 1 }}. {{ s.title }}</b>
                        <small>{{ s.phase }} · {{ s.agent }}</small>
                      </button>
                    </aside>
                    <div v-if="aiThinkStep" class="ai-think-detail">
                      <h4>{{ aiThinkStep.title }}</h4>
                      <p class="muted sm">{{ aiThinkStep.phase }} · {{ aiThinkStep.agent }}</p>
                      <div class="ai-think-block"><label>线索摘要</label><p>{{ aiThinkStep.clue || '—' }}</p></div>
                      <div class="ai-think-block"><label>初始假设</label><p>{{ aiThinkStep.hypothesis || '—' }}</p></div>
                      <div class="ai-think-block">
                        <label>推理过程</label>
                        <ul><li v-for="(r, ri) in (aiThinkStep.reasoning || [])" :key="ri">{{ r }}</li></ul>
                      </div>
                      <div class="ai-think-block"><label>观察结果</label><p>{{ aiThinkStep.observation || '—' }}</p></div>
                      <div class="ai-think-block" v-if="(aiThinkStep.evidence || []).length">
                        <label>本步 AI 证据</label>
                        <ul class="ai-evidence-list">
                          <li v-for="(ev, ei) in aiThinkStep.evidence" :key="ei">{{ ev }}</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
                <p v-else class="muted">暂无思维链</p>
              </div>

              <div v-show="aiTab === 'logs'" class="ai-tab-pane ai-logs-pane">
                <div class="ai-section-hd">
                  <div>
                    <label>日志取证</label>
                    <span class="muted sm">Agent 回传时间线 / 调查日志（含重点安全样本）· 点击分类筛选</span>
                  </div>
                  <span class="muted sm">
                    规则库 {{ aiResult.pack_stats?.log_rules_indexed || 0 }} ·
                    命中 {{ (aiResult.result?.log_rule_hits || []).length }}
                  </span>
                </div>
                <div class="ai-log-cats">
                  <button
                    type="button"
                    class="chip soft"
                    :class="{ on: !aiLogCat }"
                    @click="aiLogCat = ''"
                  >全部 {{ aiForensicsLogs.length }}</button>
                  <button
                    v-for="(n, k) in aiLogCategoryMap"
                    :key="k"
                    type="button"
                    class="chip soft"
                    :class="{ on: aiLogCat === k }"
                    @click="aiLogCat = (aiLogCat === k ? '' : k)"
                  >{{ k }} {{ n }}</button>
                  <span v-if="!Object.keys(aiLogCategoryMap).length" class="muted">分类为空</span>
                </div>
                <div class="ai-log-board">
                  <div class="ai-log-main">
                    <header class="ai-panel-hd">
                      <h4>回传日志 {{ aiLogCat ? '· ' + aiLogCat : '' }}</h4>
                      <span class="muted sm">{{ aiFilteredForensicsLogs.length }} 条</span>
                    </header>
                    <div class="ai-log-table-wrap">
                      <table class="ai-mini-tbl">
                        <thead>
                          <tr><th>时间</th><th>类型</th><th>分类</th><th>摘要 / 命令行</th></tr>
                        </thead>
                        <tbody>
                          <tr
                            v-for="(l, i) in aiFilteredForensicsLogs.slice(0, 80)"
                            :key="i"
                            :class="{ on: aiLogIdx === i }"
                            @click="aiLogIdx = i"
                          >
                            <td class="muted">{{ l.ts || '—' }}</td>
                            <td class="mono">{{ l.etype || '—' }}</td>
                            <td>
                              <button type="button" class="chip soft sm" @click.stop="aiLogCat = l.category || ''">
                                {{ l.category || 'other' }}
                              </button>
                            </td>
                            <td :title="l.command_line || l.summary">{{ l.summary || l.command_line || '—' }}</td>
                          </tr>
                          <tr v-if="!aiFilteredForensicsLogs.length">
                            <td colspan="4" class="muted">当前分类无日志。可切「全部」，或确认 Agent 已上报 Winlog / 持久化 / 进程事件。</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                    <aside v-if="aiLogCard" class="ai-log-card">
                      <b>{{ aiLogCard.etype || '日志' }}</b>
                      <p class="muted sm">{{ aiLogCard.ts || '—' }} · {{ aiLogCard.category || 'other' }}</p>
                      <p>{{ aiLogCard.summary || '—' }}</p>
                      <p v-if="aiLogCard.command_line" class="mono sm">{{ aiLogCard.command_line }}</p>
                      <p v-if="aiLogCard.path" class="mono sm">{{ aiLogCard.path }}</p>
                    </aside>
                  </div>
                  <div class="ai-log-side">
                    <header class="ai-panel-hd">
                      <h4>日志规则命中</h4>
                      <span class="muted sm">对照 log_rules / logrules</span>
                    </header>
                    <div class="ai-log-table-wrap">
                      <table class="ai-mini-tbl">
                        <thead><tr><th>规则</th><th>来源</th><th>证据</th></tr></thead>
                        <tbody>
                          <tr v-for="(h, i) in (aiResult.result?.log_rule_hits || []).slice(0, 40)" :key="i">
                            <td>{{ h.rule_title || '—' }}</td>
                            <td class="mono">{{ h.source || h.match || '—' }}</td>
                            <td :title="h.evidence">{{ h.evidence || h.etype || '—' }}</td>
                          </tr>
                          <tr v-if="!(aiResult.result?.log_rule_hits || []).length">
                            <td colspan="3" class="muted">暂无规则命中（增强对照，分析不依赖此项）。</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </div>

              <div v-show="aiTab === 'entity'" class="ai-tab-pane ai-entity-pane">
                <div class="ai-section-hd">
                  <div>
                    <label>实体研判</label>
                    <span class="muted sm">
                      共 {{ (aiResult.result?.entities || []).length }} ·
                      恶意 {{ aiEntityStats.malicious }} ·
                      可疑 {{ aiEntityStats.suspicious }} ·
                      IoC {{ (aiResult.result?.iocs || []).length }}
                    </span>
                  </div>
                  <button type="button" class="btn-text sm" @click="aiTab = 'resp'">去处置 →</button>
                </div>
                <div v-if="(aiResult.result?.entities || []).length" class="ai-entity-board">
                  <div class="ai-entity-list">
                    <button
                      v-for="(e, i) in aiResult.result.entities"
                      :key="i"
                      type="button"
                      class="ai-entity-row"
                      :class="{ on: aiEntityIdx === i }"
                      :data-risk="e.risk || ''"
                      @click="aiEntityIdx = i"
                    >
                      <span class="ai-entity-type">{{ e.type || 'obj' }}</span>
                      <span class="ai-entity-main">
                        <b :title="e.value">{{ e.value || '—' }}</b>
                        <small>{{ e.reason || e.analysis?.conclusion || '—' }}</small>
                      </span>
                      <span class="pill" :data-risk="e.risk">{{ e.risk || '—' }}</span>
                    </button>
                  </div>
                  <aside v-if="aiEntityCard" class="ai-entity-detail">
                    <div class="ai-entity-detail-top">
                      <span class="pill" :data-risk="aiEntityCard.risk">{{ aiEntityCard.risk || '—' }}</span>
                      <em>{{ aiEntityCard.type || 'entity' }}</em>
                      <span v-if="aiEntityCard.action" class="chip soft">剧本 {{ aiEntityCard.action }}</span>
                    </div>
                    <h4 class="mono">{{ aiEntityCard.value }}</h4>
                    <div class="ai-entity-grid">
                      <div class="ai-entity-box">
                        <label>基本信息</label>
                        <dl>
                          <div><dt>PID</dt><dd>{{ aiEntityCard.analysis?.basic?.pid ?? aiEntityCard.pid ?? '—' }}</dd></div>
                          <div><dt>路径</dt><dd class="mono">{{ aiEntityCard.analysis?.basic?.path || aiEntityCard.path || '—' }}</dd></div>
                          <div class="full" v-if="aiEntityCard.analysis?.basic?.command_line || aiEntityCard.command_line">
                            <dt>命令行</dt>
                            <dd class="mono">{{ aiEntityCard.analysis?.basic?.command_line || aiEntityCard.command_line }}</dd>
                          </div>
                        </dl>
                      </div>
                      <div class="ai-entity-box">
                        <label>研判过程</label>
                        <ol>
                          <li v-for="(p, pi) in (aiEntityCard.analysis?.process || ['暂无过程说明'])" :key="pi">{{ p }}</li>
                        </ol>
                      </div>
                      <div class="ai-entity-box accent">
                        <label>研判结论</label>
                        <p>{{ aiEntityCard.analysis?.conclusion || aiEntityCard.reason || '—' }}</p>
                      </div>
                      <div class="ai-entity-box advice">
                        <label>处置建议</label>
                        <p>{{ aiEntityCard.analysis?.advice || '—' }}</p>
                      </div>
                    </div>
                    <div v-if="(aiResult.result?.iocs || []).length" class="ai-ioc-strip">
                      <label>相关 IoC</label>
                      <div class="ai-ioc-chips">
                        <span v-for="(x, i) in aiResult.result.iocs.slice(0, 12)" :key="i" class="chip soft">
                          <b>{{ x.type }}</b> {{ x.value }}
                        </span>
                      </div>
                    </div>
                    <div class="ai-threat-actions">
                      <button type="button" class="btn sm" @click="aiTab = 'threats'">看 AI 研判事件</button>
                      <button type="button" class="btn sm" @click="aiTab = 'resp'">去处置</button>
                    </div>
                  </aside>
                </div>
                <div v-else class="ai-panel-empty fill">暂无实体。分析完成后会从威胁/日志抽出进程、文件、IP、注册表等。</div>
              </div>

              <div v-show="aiTab === 'report'" class="ai-tab-pane ai-report-pane">
                <div class="ai-section-hd">
                  <div>
                    <label>调查报告</label>
                    <span class="muted sm">
                      {{ aiResult.result?.verdict || '—' }} ·
                      {{ aiResult.result?.risk_level || '—' }} /
                      {{ aiResult.result?.risk_score ?? '—' }} ·
                      {{ aiResult.llm_refined || aiResult.result?.llm_refined ? '模型已精炼' : (aiResult.mode || 'Agent Team') }}
                    </span>
                  </div>
                  <div class="ai-report-actions">
                    <button type="button" class="btn-text sm" @click="aiTab = 'think'">思维链</button>
                    <button type="button" class="btn-text sm" @click="aiTab = 'resp'">处置 →</button>
                  </div>
                </div>
                <div class="ai-report-board">
                  <article class="ai-md ai-report-doc" v-html="aiMarkdownHtml" />
                  <aside class="ai-report-side">
                    <div class="ai-report-card verdict" :data-v="aiResult.result?.verdict || ''">
                      <label>AI 定性</label>
                      <b>{{ aiResult.result?.verdict || '待研判' }}</b>
                      <small>风险 {{ aiResult.result?.risk_level || '—' }} · {{ aiResult.result?.risk_score ?? '—' }}/100</small>
                    </div>
                    <div class="ai-report-card" v-if="aiResult.result?.root_cause">
                      <label>根因摘要</label>
                      <p>{{ aiResult.result.root_cause }}</p>
                    </div>
                    <div class="ai-report-card" v-if="(aiResult.result?.highlights || []).length">
                      <label>关键证据</label>
                      <ul>
                        <li v-for="(h, i) in aiResult.result.highlights.slice(0, 8)" :key="i">{{ h }}</li>
                      </ul>
                    </div>
                    <div class="ai-report-card" v-if="(aiResult.skills_used || []).length">
                      <label>使用 Skill</label>
                      <div class="ai-ioc-chips">
                        <span v-for="s in aiResult.skills_used" :key="s.id" class="chip soft" :title="(s.why || []).join('；')">
                          {{ s.name || s.id }}
                        </span>
                      </div>
                    </div>
                    <div class="ai-report-card" v-if="(aiResult.result?.iocs || []).length">
                      <label>IoC</label>
                      <ul class="ai-ioc-list">
                        <li v-for="(x, i) in aiResult.result.iocs.slice(0, 10)" :key="i">
                          <b>{{ x.type }}</b> <code>{{ x.value }}</code>
                        </li>
                      </ul>
                    </div>
                    <p v-if="aiResult.error" class="hint warn">模型回退：{{ aiResult.error }}</p>
                  </aside>
                </div>
              </div>

              <div v-show="aiTab === 'resp'" class="ai-tab-pane">
                <div v-if="(aiResult.result?.dispositions || []).length" class="ai-disp">
                  <label>推荐处置 <em class="muted">（需人工审核）</em></label>
                  <div class="ai-disp-list">
                    <div v-for="(d, i) in aiResult.result.dispositions" :key="i" class="ai-disp-row">
                      <div>
                        <b>{{ d.label }}</b>
                        <span class="mono">{{ d.target }}</span>
                        <small>{{ d.reason }}</small>
                      </div>
                      <button
                        v-if="d.action && d.action !== 'review'"
                        type="button"
                        class="btn sm danger-outline"
                        :disabled="aiDispBusy"
                        @click="runAiDisposition(d)"
                      >审核并下发</button>
                      <button v-else type="button" class="btn sm" @click="goMenu('events')">去威胁事件</button>
                    </div>
                  </div>
                </div>
                <div v-if="(aiResult.result?.hardening || []).length" class="ai-hard">
                  <label>体系化加固建议</label>
                  <ul>
                    <li v-for="(h, i) in aiResult.result.hardening" :key="i">
                      <b>{{ h.title }}</b>
                      <span>{{ h.detail }}</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>

            <div v-else class="ai-empty">
              <p>请选择左侧<strong>在线终端</strong>，点击后自动开始分析。</p>
              <p class="muted">分析内容包含：Agent 实时快照（进程/服务/任务/启动项/网络/文件等）、威胁事件，以及近 24 小时终端日志（登录/PowerShell/计划任务/服务/注册表/外联等）。</p>
            </div>
          </main>
        </div>
      </section>

      <!-- ========== ATT&CK 看板 ========== -->
      <section v-else-if="page === 'attck'" class="page attck-page">
        <header class="page-hd">
          <div>
            <h1>ATT&CK 看板</h1>
            <p class="desc">与威胁事件同源映射 · 热力总览 · 告警下钻</p>
          </div>
          <div class="hd-right">
            <span class="live-hint" :class="{ on: liveOk }">
              <i class="live-dot" />
              {{ liveOk ? `已连接 · ${liveAgo}` : '连接中…' }}
            </span>
            <select v-model="attckAgent" class="search sev-filter" @change="loadAttckBoard">
              <option value="">全部主机</option>
              <option v-for="a in agents" :key="a.agent_id" :value="a.agent_id">{{ a.hostname || short(a.agent_id) }}</option>
            </select>
            <select v-model.number="attckDays" class="search sev-filter" @change="loadAttckBoard">
              <option :value="0">全部时间</option>
              <option :value="1">近 1 天</option>
              <option :value="7">近 7 天</option>
              <option :value="30">近 30 天</option>
            </select>
            <button type="button" class="btn ghost-btn" @click="loadAttckBoard">立即同步</button>
          </div>
        </header>

        <div class="ov-kpis ak-kpis">
          <article class="kpi click" @click="goMenu('events')">
            <span>威胁事件</span>
            <strong class="c-danger">{{ attckTotal }}</strong>
            <em>不含已加白 / 无需处置</em>
          </article>
          <article class="kpi click" @click="goMenu('events')">
            <span>未处置</span>
            <strong class="c-warn">{{ attckOpen }}</strong>
            <em>待研判处置</em>
          </article>
          <article class="kpi">
            <span>高危 / 严重</span>
            <strong class="c-danger">{{ attckHigh }}</strong>
            <em>优先响应</em>
          </article>
          <article class="kpi">
            <span>覆盖战术</span>
            <strong class="c-ink">{{ attckCovered }}<small class="kpi-den">/{{ attckHeat.length || 12 }}</small></strong>
            <em>MITRE ATT&CK 战术</em>
          </article>
          <article class="kpi">
            <span>命中技术</span>
            <strong class="c-ink">{{ attckTop.length }}</strong>
            <em>{{ attckUnmapped ? `另有 ${attckUnmapped} 条未映射` : '技术去重' }}</em>
          </article>
        </div>

        <div class="ak-board">
          <div class="panel ak-chain">
            <div class="panel-hd">
              <div>
                <h3>攻击链路</h3>
                <span class="meta">12 战术矩阵 · 点选筛选下方技术与告警</span>
              </div>
              <button v-if="attckSel.tactic || attckSel.tech" type="button" class="btn-text" @click="clearAttckSel">清除筛选</button>
            </div>
            <div class="ak-steps">
              <button
                v-for="(t, i) in attckHeat"
                :key="t.tactic"
                type="button"
                class="ak-step"
                :class="{ hit: t.count, on: attckSel.tactic === t.tactic }"
                :style="attckStepStyle(t)"
                @click="selectAttckTactic(t.tactic)"
              >
                <div class="ak-step-top">
                  <span class="ak-no">{{ String(i + 1).padStart(2, '0') }}</span>
                  <b>{{ t.name }}</b>
                </div>
                <div class="ak-step-bot">
                  <strong>{{ t.count || 0 }}</strong>
                  <em>
                    <template v-if="t.techniques.length">{{ t.techniques.length }} 项技术<template v-if="t.high"> · 高危 {{ t.high }}</template></template>
                    <template v-else>未发现</template>
                  </em>
                </div>
              </button>
            </div>
          </div>

          <div class="ak-mid">
            <div class="panel ak-tech">
              <div class="panel-hd">
                <div>
                  <h3>技术分布</h3>
                  <span class="meta">{{ attckSelTacticName ? `战术：${attckSelTacticName}` : '全部战术' }} · 点击筛选告警</span>
                </div>
              </div>
              <div v-if="attckTechList.length" class="ak-tech-list">
                <button
                  v-for="t in attckTechList"
                  :key="t.id"
                  type="button"
                  class="ak-tech-row"
                  :class="{ on: attckSel.tech === t.id }"
                  @click="selectAttckTech(t)"
                >
                  <code>{{ t.id }}</code>
                  <span class="ak-tech-name" :title="t.name">{{ t.name || '—' }}</span>
                  <span class="ak-tac">{{ t.tactic_name || attckSelTacticName || '—' }}</span>
                  <i class="rank-bar"><i :style="{ width: attckRankPct(t.count) + '%' }" /></i>
                  <strong>{{ t.count }}</strong>
                </button>
              </div>
              <p v-else class="empty sm">{{ attckSel.tactic ? '该战术下暂无命中技术' : '暂无命中技术' }}</p>
            </div>

            <div class="panel ak-hosts">
              <div class="panel-hd">
                <div>
                  <h3>告警主机</h3>
                  <span class="meta">点击只看该主机</span>
                </div>
                <button v-if="attckAgent" type="button" class="btn-text" @click="attckAgent = ''; loadAttckBoard()">全部主机</button>
              </div>
              <div v-if="attckHosts.length" class="attck-rank">
                <button
                  v-for="(h, i) in attckHosts"
                  :key="h.host || h.agent_id || i"
                  type="button"
                  class="rank-row"
                  :class="{ on: attckAgent && attckAgent === h.agent_id }"
                  @click="filterAttckByHost(h)"
                >
                  <em>{{ i + 1 }}</em>
                  <div class="rank-main">
                    <b>{{ h.host || h.hostname || short(h.agent_id) }}</b>
                    <i class="rank-bar host"><i :style="{ width: attckHostPct(h.count) + '%' }" /></i>
                  </div>
                  <strong>{{ h.count }}</strong>
                </button>
              </div>
              <p v-else class="empty sm">暂无</p>
            </div>
          </div>
        </div>

        <div class="panel attck-recent">
          <div class="panel-hd">
            <div>
              <h3>映射告警</h3>
              <span class="meta">
                <template v-if="attckSel.tactic || attckSel.tech">
                  筛选：{{ [attckSelTacticName, attckSel.tech].filter(Boolean).join(' / ') }} ·
                </template>
                共 {{ attckFiltered.length }} 条 · 点行看详情，点「威胁视图」进入处置
                <template v-if="attckFiltered.length > 60">（显示最近 60 条）</template>
              </span>
            </div>
            <div class="hd-right">
              <button type="button" class="btn sm" @click="goMenu('behaviors')">检出行为</button>
              <button type="button" class="btn sm" @click="goMenu('events')">全部威胁 →</button>
            </div>
          </div>
          <div class="table-scroll" v-if="attckFiltered.length">
            <table class="evt-table">
              <thead>
                <tr>
                  <th style="width:140px">时间</th>
                  <th style="width:72px">级别</th>
                  <th>告警</th>
                  <th style="width:220px">技术</th>
                  <th style="width:96px">战术</th>
                  <th style="width:140px">主机</th>
                  <th style="width:72px">状态</th>
                  <th style="width:88px">操作</th>
                </tr>
              </thead>
              <tbody>
                <template v-for="it in attckFiltered.slice(0, 60)" :key="it.id">
                  <tr
                    class="row-click"
                    :class="{ on: listFocusId === it.id }"
                    @click="selectListEvent({ id: it.id, title: it.title, severity: it.severity, hostname: it.hostname, agent_id: it.agent_id, status: it.status, created_at: it.ts, updated_at: it.ts, module: it.module, detail: it.detail, detail_obj: it.detail_obj })"
                  >
                    <td class="mono">{{ fmtTime(it.ts) }}</td>
                    <td><span class="sev" :data-s="it.severity">{{ sevLabel(it.severity) }}</span></td>
                    <td class="strong ak-title" :title="it.title">{{ it.title }}</td>
                    <td>
                      <span v-if="it.technique" class="ak-techcell"><code>{{ it.technique }}</code>{{ it.technique_name }}</span>
                      <span v-else class="muted">未映射</span>
                    </td>
                    <td class="muted">{{ it.tactic ? it.tactic_name : '—' }}</td>
                    <td>{{ it.hostname || short(it.agent_id) }}</td>
                    <td><span class="ak-st" :data-s="it.status">{{ statusLabel(it.status || 'open') }}</span></td>
                    <td class="ops" @click.stop>
                      <button type="button" class="op-ico primary" title="威胁视图" @click="openEventById(it.id)">视</button>
                    </td>
                  </tr>
                  <tr v-if="listFocusId === it.id && listFocusEvent" class="evt-expand-row" :ref="(el) => scrollExpandIntoView(el)">
                    <td colspan="8">
                      <div class="evt-inline">
                        <div class="ep-hd">
                          <div class="ep-title">
                            <span class="sev" :data-s="listFocusEvent.severity">{{ sevLabel(listFocusEvent.severity) }}</span>
                            <b>{{ listFocusEvent.title }}</b>
                          </div>
                          <div class="ep-acts">
                            <button type="button" class="btn sm primary" @click.stop="openEvent(listFocusEvent)">威胁视图 →</button>
                            <button type="button" class="btn sm" @click.stop="openAllow(listFocusEvent)">加白</button>
                            <button type="button" class="btn-text" @click.stop="clearListFocus">收起</button>
                          </div>
                        </div>
                        <div class="ep-grid">
                          <div class="ep-col">
                            <h4>对象信息</h4>
                            <dl class="td-dl">
                              <div><dt>名称</dt><dd>{{ listEvidenceName || '—' }}</dd></div>
                              <div><dt>路径 / 命令</dt><dd class="mono">{{ listEvidencePath || '—' }}</dd></div>
                              <div><dt>主机</dt><dd>{{ listFocusEvent.hostname || short(listFocusEvent.agent_id) }}</dd></div>
                              <div><dt>模块</dt><dd>{{ modLabel(listFocusEvent.module) || '—' }}</dd></div>
                            </dl>
                          </div>
                          <div class="ep-col">
                            <h4>威胁信息</h4>
                            <dl class="td-dl">
                              <div><dt>技术</dt><dd>{{ it.technique ? `${it.technique} ${it.technique_name || ''}`.trim() : '未映射' }}</dd></div>
                              <div><dt>战术</dt><dd>{{ it.tactic_name || '—' }}</dd></div>
                              <div><dt>匹配特征</dt><dd class="mono">{{ listEventEvidence.matched || '—' }}</dd></div>
                              <div><dt>判定</dt><dd>{{ judgeOf(listFocusEvent) }}</dd></div>
                            </dl>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>
          <p v-else class="empty sm">{{ (attckSel.tactic || attckSel.tech) ? '当前筛选下没有告警' : '当前时间范围内暂无威胁事件' }}</p>
        </div>
      </section>

      <!-- ========== IOC ========== -->
      <section v-else-if="page === 'ioc'" class="page">
        <header class="page-hd">
          <div>
            <h1>威胁情报 IOC</h1>
            <p class="desc">本地自定义 IOC + 情报库 ioc_data.db 精确匹配（哈希 / IP / 域名）</p>
          </div>
          <button type="button" class="btn" @click="loadIoc">刷新</button>
        </header>
        <div class="panel pad ioc-lib" v-if="iocLib">
          <div class="ioc-lib-row">
            <div>
              <b>情报库</b>
              <p class="muted mono">{{ iocLib.path || 'ioc/ioc_data.db' }}</p>
            </div>
            <div class="ioc-lib-stat">
              <span>条目 <b>{{ fmtNum(iocLib.count) }}</b></span>
              <span>本地启用 <b>{{ iocLibLocal }}</b></span>
              <span :class="iocLib.exists === false ? 'off' : 'on'">{{ iocLib.exists === false ? '未找到' : '已加载' }}</span>
            </div>
          </div>
          <p class="hint" v-if="iocLib.hint">{{ iocLib.hint }}</p>
        </div>
        <div class="panel pad">
          <h3 style="margin:0 0 10px">本地自定义 IOC</h3>
          <div class="hunt-bar">
            <select v-model="iocType" class="search sev-filter">
              <option value="hash">hash</option>
              <option value="domain">domain</option>
              <option value="ip">ip</option>
              <option value="path">path</option>
              <option value="process">process</option>
              <option value="cmdline">cmdline</option>
            </select>
            <button type="button" class="btn primary" @click="doImportIoc">批量导入</button>
          </div>
          <textarea v-model="iocText" class="field" rows="5" placeholder="每行一个 IOC；也可 type:value，如 domain:evil.com" />
          <table v-if="iocItems.length" style="margin-top:14px">
            <thead><tr><th>类型</th><th>值</th><th>级别</th><th>命中</th><th>备注</th><th></th></tr></thead>
            <tbody>
              <tr v-for="x in iocItems" :key="x.id">
                <td>{{ x.ioc_type }}</td>
                <td class="mono">{{ x.value }}</td>
                <td><span class="sev" :data-s="x.severity">{{ sevLabel(x.severity) }}</span></td>
                <td>{{ x.hits || 0 }}</td>
                <td>{{ x.note || '—' }}</td>
                <td><button type="button" class="btn-text" style="color:var(--danger)" @click="delIoc(x.id)">删除</button></td>
              </tr>
            </tbody>
          </table>
          <p v-else class="empty sm">暂无本地 IOC（情报库仍会自动匹配时间线哈希/IP）</p>
        </div>
      </section>

      <!-- ========== 灰度升级 ========== -->
      <section v-else-if="page === 'upgrade'" class="page">
        <header class="page-hd">
          <div>
            <h1>灰度升级</h1>
            <p class="desc">上传 Agent 二进制 → 选择终端推送 upgrade 指令（校验 sha256 后替换）</p>
          </div>
          <button type="button" class="btn" @click="loadUpgradePage">刷新</button>
        </header>
        <div class="deploy-grid">
          <article class="panel pad">
            <h3>上传升级包</h3>
            <label class="form-lab">
              <span>版本号</span>
              <input v-model="upVer" class="field" placeholder="如 0.7.0" />
            </label>
            <label class="form-lab">
              <span>备注</span>
              <input v-model="upNote" class="field" placeholder="可选" />
            </label>
            <label class="form-lab">
              <span>forensic-agent.exe</span>
              <input type="file" accept=".exe" @change="onUpFile" />
            </label>
            <button type="button" class="btn primary" :disabled="upBusy || !upFile" @click="doUploadUpgrade">
              {{ upBusy ? '上传中…' : '上传' }}
            </button>
            <p v-if="upError" class="err-text">{{ upError }}</p>
            <p v-if="upOk" class="hint">{{ upOk }}</p>
          </article>
          <article class="panel pad">
            <h3>选择终端并推送</h3>
            <div class="hunt-bar">
              <select v-model="upPkgId" class="search grow">
                <option value="">选择已上传的包</option>
                <option v-for="p in upPackages" :key="p.id" :value="p.id">
                  {{ p.version }} · {{ short(p.sha256) }} · {{ fmtSize(p.size) }}
                </option>
              </select>
            </div>
            <div class="up-hosts">
              <label v-for="a in agents" :key="a.agent_id" class="chk">
                <input type="checkbox" :value="a.agent_id" v-model="upAgentIds" />
                {{ a.hostname || short(a.agent_id) }}
                <em class="muted">{{ a.version || '?' }} {{ a.online ? '在线' : '离线' }}</em>
              </label>
            </div>
            <div class="row" style="margin-top:12px">
              <button type="button" class="btn" @click="upAgentIds = agents.map(a => a.agent_id)">全选</button>
              <button type="button" class="btn" @click="upAgentIds = agents.filter(a => a.online).map(a => a.agent_id)">仅在线</button>
              <button type="button" class="btn primary" :disabled="upPushBusy || !upPkgId || !upAgentIds.length" @click="doPushUpgrade">
                {{ upPushBusy ? '推送中…' : `灰度推送 (${upAgentIds.length})` }}
              </button>
              <button type="button" class="btn danger-outline" :disabled="upPushBusy || !upAgentIds.length" @click="doRollbackUpgrade">
                回滚升级
              </button>
            </div>
          </article>
        </div>
        <div class="panel pad" style="margin-top:14px" v-if="upPackages.length">
          <h3>已上传包</h3>
          <table>
            <thead><tr><th>版本</th><th>SHA256</th><th>大小</th><th>时间</th><th></th></tr></thead>
            <tbody>
              <tr v-for="p in upPackages" :key="p.id">
                <td>{{ p.version }}</td>
                <td class="mono muted">{{ p.sha256 }}</td>
                <td>{{ fmtSize(p.size) }}</td>
                <td>{{ fmtTime(p.created_at) }}</td>
                <td>
                  <button type="button" class="btn-text" @click="upPkgId = p.id">选用</button>
                  <button type="button" class="btn-text" style="color:var(--danger)" @click="doDelUpgrade(p.id)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="panel pad" style="margin-top:14px" v-if="upgradeDriftRows.length">
          <h3>组件漂移（expected vs actual）</h3>
          <p class="muted sm">服务端集成期望 vs 终端 health.components；PolicyApplied / sync_rev 未收敛一并展示。</p>
          <table>
            <thead>
              <tr><th>终端</th><th>缺失</th><th>失败/降级</th><th>sync</th><th>策略</th></tr>
            </thead>
            <tbody>
              <tr v-for="row in upgradeDriftRows" :key="row.agent_id">
                <td>{{ row.hostname || short(row.agent_id) }}</td>
                <td class="mono sm">{{ (row.missing || []).join(', ') || '—' }}</td>
                <td class="mono sm">{{ [...(row.failed||[]), ...(row.degraded||[])].join(', ') || '—' }}</td>
                <td>{{ row.sync_drift ? `${row.local_sync_rev}<${row.server_sync_rev}` : 'OK' }}</td>
                <td>{{ row.policy_drift ? '未收敛' : 'OK' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="panel pad" style="margin-top:14px">
          <h3>灰度状态（升级 Details / PolicyApplied）</h3>
          <p class="muted sm">对齐 Elastic cproto：state 7=UPGRADING、8=ROLLBACK；state_name 为细粒度阶段。</p>
          <table v-if="upgradeFleetRows.length">
            <thead>
              <tr>
                <th>终端</th>
                <th>版本</th>
                <th>PolicyApplied</th>
                <th>local sync / policy rev</th>
                <th>升级 Details</th>
                <th>遥测 / sync</th>
                <th>最近 upgrade 指令</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in upgradeFleetRows" :key="row.agent_id">
                <td>{{ row.hostname || short(row.agent_id) }} <em class="muted">{{ row.online ? '在线' : '离线' }}</em></td>
                <td class="mono">{{ row.version || '—' }}</td>
                <td>
                  <span class="pill" :class="{ on: row.policy_applied }">{{ row.policy_applied ? '已收敛' : '同步中' }}</span>
                </td>
                <td class="mono muted">{{ row.local_sync_rev }} / {{ row.local_policy_rev }}</td>
                <td class="mono sm">{{ row.upgrade_details || '—' }}</td>
                <td class="mono sm" :title="row.telemetry_hint">{{ row.telemetry_line || '—' }}</td>
                <td class="mono sm">{{ row.last_upgrade_cmd || '—' }}</td>
                <td>
                  <button type="button" class="btn-text" :disabled="!row.online || !row.upgrade_details" @click="cancelHostUpgrade(row)">取消升级</button>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-else class="empty sm">暂无终端数据，请先刷新或等待 Agent 心跳。</p>
        </div>
        <div class="panel pad" style="margin-top:14px">
          <div class="panel-hd" style="display:flex;justify-content:space-between;align-items:center">
            <h3>诊断包历史</h3>
            <button type="button" class="btn sm" @click="loadDiagHistory">刷新</button>
          </div>
          <table v-if="diagHistoryItems.length">
            <thead><tr><th>终端</th><th>指令</th><th>文件</th><th>大小</th><th></th></tr></thead>
            <tbody>
              <tr v-for="d in diagHistoryItems" :key="d.agent_id + d.command_id">
                <td class="mono sm">{{ short(d.agent_id) }}</td>
                <td class="mono sm">{{ d.command_id }}</td>
                <td class="mono sm">{{ d.filename }}</td>
                <td>{{ Math.round((d.size || 0) / 1024) }} KB</td>
                <td><button type="button" class="btn-text" @click="downloadAgentDiagnostics(d.agent_id, d.command_id)">下载</button></td>
              </tr>
            </tbody>
          </table>
          <p v-else class="empty sm">暂无已落盘诊断包</p>
        </div>
      </section>

      <!-- ========== 行为序列 ========== -->
      <section v-else-if="page === 'seq'" class="page seq-page">
        <header class="page-hd">
          <div>
            <h1>行为序列规则</h1>
            <p class="desc">
              在主机时间线的时间窗口内，按顺序命中多步行为（如「Word 创建 → PowerShell 出现」），用于发现单条特征看不出的攻击链。
            </p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn" @click="loadSeqRules">刷新</button>
            <button type="button" class="btn primary" @click="startCreateSeq">新增序列</button>
          </div>
        </header>

        <div class="seq-explain panel pad">
          <b>什么是行为序列？</b>
          <p>
            Agent 规则是「单条快照命中」；行为序列是「多条时间线事件按顺序出现」。
            例如 180 秒内先出现办公软件进程，再出现 PowerShell，就会告警——对应钓鱼宏常见攻击链。
          </p>
        </div>

        <div class="rules-layout">
          <div class="panel fill">
            <div class="panel-hd">
              <h3>序列列表 ({{ seqRules.length }})</h3>
              <span class="meta">启用 {{ seqRules.filter(r => r.enabled).length }} 条</span>
            </div>
            <div class="table-scroll">
              <table v-if="seqRules.length">
                <thead>
                  <tr>
                    <th>启用</th>
                    <th>标题</th>
                    <th>窗口</th>
                    <th>级别</th>
                    <th>步骤</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="r in seqRules"
                    :key="r.id"
                    class="row-click"
                    :class="{ active: editingSeq?.id === r.id && !seqCreating }"
                    @click="startEditSeq(r)"
                  >
                    <td @click.stop>
                      <label class="switch">
                        <input type="checkbox" :checked="!!r.enabled" @change="toggleSeq(r, $event.target.checked)" />
                        <i />
                      </label>
                    </td>
                    <td>
                      <b class="strong">{{ r.title }}</b>
                      <div class="meta">{{ r.note || r.id }}</div>
                    </td>
                    <td>{{ r.window_sec }}s</td>
                    <td><span class="sev" :data-s="r.severity">{{ sevLabel(r.severity) }}</span></td>
                    <td class="muted">{{ seqStepsPreview(r) }}</td>
                    <td class="ops" @click.stop>
                      <button type="button" class="link" @click="startEditSeq(r)">编辑</button>
                      <button type="button" class="link danger" @click="removeSeq(r)">删除</button>
                    </td>
                  </tr>
                </tbody>
              </table>
              <p v-else class="empty">暂无序列规则，点击右上角新增</p>
            </div>
          </div>

          <aside class="panel pad rule-editor">
            <h3>{{ seqCreating ? '新增序列' : (editingSeq ? '编辑序列' : '序列编辑') }}</h3>
            <p v-if="!seqCreating && !editingSeq" class="hint">选中左侧编辑，或点击「新增序列」。至少配置 2 步（A→B）。</p>
            <template v-if="seqCreating || editingSeq">
              <div v-if="seqCreating" class="form-lab">
                <span>快速模板</span>
                <div class="chip-row">
                  <button
                    v-for="t in SEQ_TEMPLATES"
                    :key="t.id"
                    type="button"
                    class="chip-btn"
                    @click="applySeqTemplate(t)"
                  >{{ t.label }}</button>
                </div>
              </div>
              <label class="form-lab">
                <span>标题 *</span>
                <input v-model="seqForm.title" class="field" placeholder="例如：办公进程后出现 PowerShell" />
              </label>
              <div class="form-row2">
                <label class="form-lab">
                  <span>严重级别</span>
                  <select v-model="seqForm.severity" class="field">
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                  </select>
                </label>
                <label class="form-lab">
                  <span>时间窗口（秒）</span>
                  <input v-model.number="seqForm.window_sec" type="number" min="10" max="3600" class="field" />
                </label>
              </div>
              <div class="form-lab">
                <span>步骤序列 *（按时间先后，至少 2 步）</span>
                <div v-for="(st, idx) in seqForm.steps" :key="idx" class="seq-step">
                  <header>
                    <b>第 {{ idx + 1 }} 步</b>
                    <button v-if="seqForm.steps.length > 2" type="button" class="link danger" @click="removeSeqStep(idx)">删除</button>
                  </header>
                  <label class="form-lab">
                    <span>事件类型包含</span>
                    <select v-model="st.etype_contains" class="field">
                      <option value="">不限</option>
                      <option value="process">process（进程）</option>
                      <option value="network">network（网络）</option>
                      <option value="file">file（文件）</option>
                      <option value="driver">driver（驱动）</option>
                      <option value="service">service（服务）</option>
                      <option value="registry">registry（注册表）</option>
                    </select>
                  </label>
                  <label class="form-lab">
                    <span>摘要包含</span>
                    <input v-model="st.summary_contains" class="field" placeholder="可选，如：临时" />
                  </label>
                  <label class="form-lab">
                    <span>进程名正则</span>
                    <input v-model="st.name_regex" class="field" placeholder="可选，如 (?i)powershell\.exe" />
                  </label>
                </div>
                <button type="button" class="btn" style="margin-top:8px" @click="addSeqStep" :disabled="seqForm.steps.length >= 6">
                  + 添加步骤
                </button>
              </div>
              <label class="form-lab">
                <span>备注</span>
                <input v-model="seqForm.note" class="field" placeholder="可选，如 ATT&CK 技术链说明" />
              </label>
              <label class="chk">
                <input type="checkbox" v-model="seqForm.enabled" />
                启用此序列
              </label>
              <p v-if="seqFormError" class="err-text">{{ seqFormError }}</p>
              <div class="row" style="margin-top:14px">
                <button type="button" class="btn primary" :disabled="seqSaving" @click="saveSeqForm">
                  {{ seqSaving ? '保存中…' : '保存' }}
                </button>
                <button type="button" class="btn" @click="cancelSeqForm">取消</button>
              </div>
            </template>
          </aside>
        </div>
      </section>

      <!-- ========== 终端分组 ========== -->
      <section v-else-if="page === 'groups'" class="page">
        <header class="page-hd">
          <div>
            <h1>终端分组</h1>
            <p class="desc">按业务分组管理终端（财务 / 研发等）</p>
          </div>
        </header>
        <div class="panel pad">
          <div class="hunt-bar">
            <input v-model="groupName" class="search" placeholder="分组名" />
            <input v-model="groupIds" class="search grow" placeholder="agent_id，逗号分隔" />
            <button type="button" class="btn primary" @click="saveGroup">保存分组</button>
          </div>
          <div class="host-cards padded" v-if="groupItems.length">
            <div v-for="g in groupItems" :key="g.id" class="host-card rich tile">
              <div class="hc-top"><b>{{ g.name }}</b><span class="pill">{{ (g.agent_ids||[]).length }} 台</span></div>
              <div class="hc-meta"><span>{{ (g.agent_ids||[]).join(', ') || '—' }}</span></div>
              <small class="muted">{{ g.note || '' }}</small>
            </div>
          </div>
          <p v-else class="empty sm">暂无分组</p>
        </div>
      </section>

      <!-- ========== 处置审计 ========== -->
      <section v-else-if="page === 'audit'" class="page">
        <header class="page-hd">
          <div>
            <h1>处置审计</h1>
            <p class="desc">谁在何时对哪台终端下发了什么动作</p>
          </div>
          <button type="button" class="btn" @click="loadAudit">刷新</button>
        </header>
        <div class="panel pad">
          <table v-if="auditItems.length">
            <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>终端</th><th>详情</th></tr></thead>
            <tbody>
              <tr v-for="a in auditItems" :key="a.id">
                <td>{{ fmtTime(a.created_at) }}</td>
                <td>{{ a.actor || '—' }}</td>
                <td>{{ a.action }}</td>
                <td>{{ short(a.agent_id) }}</td>
                <td class="muted" :title="a.detail">{{ (a.detail || '').slice(0, 100) }}</td>
              </tr>
            </tbody>
          </table>
          <p v-else class="empty">暂无审计记录</p>
        </div>
      </section>

      <!-- ========== 配置 ========== -->
      <section v-else-if="page === 'settings'" class="page settings-page">
        <header class="page-hd">
          <div>
            <h1>接入与地址</h1>
            <p class="desc">终端回连地址 · 接入密钥 · 实时规则启停</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn sm" @click="goMenu('deploy')">部署下载</button>
            <button type="button" class="btn sm" @click="goMenu('upgrade')">灰度升级</button>
            <button type="button" class="btn sm" @click="setSection('rules')">规则管理</button>
          </div>
        </header>

        <div class="settings-stack">
          <div class="panel pad settings-addr">
            <div class="settings-addr-row">
              <label class="grow">
                <span>EDR 平台地址</span>
                <input v-model="agentServerUrl" class="field" :disabled="!isAdmin" placeholder="http://192.168.31.94:8100" />
              </label>
              <div v-if="isAdmin" class="settings-addr-acts">
                <button type="button" class="btn primary" :disabled="saving" @click="saveSettings">{{ saving ? '保存中…' : '保存' }}</button>
                <button type="button" class="btn" @click="rotateKey">轮换接入密钥</button>
              </div>
            </div>
            <p class="hint">填终端能访问到的 EDR 后台地址（勿用 127.0.0.1）。留空则按当前浏览器地址生成安装包。轮换密钥后需重新下载安装包。</p>
          </div>

          <div v-if="isAdmin" class="panel pad">
            <h3 style="margin:0 0 8px;font-size:15px">运维</h3>
            <label class="chk">
              <input type="checkbox" :checked="autoEnrichOnLoad" @change="setAutoEnrichOnLoad($event.target.checked)" />
              刷新威胁列表时自动 enrich 详情（最多 120 条，仅管理员）
            </label>
            <p class="hint sm">补全历史告警命令行/PTM 链；大库时可能增加 SQLite 写入，按需开启。</p>
          </div>

          <div class="panel settings-rules-panel">
            <div class="panel-hd">
              <div>
                <h3>实时匹配规则</h3>
                <span class="meta">
                  {{ ruleStats?.source || 'Agent 独立规则库' }}
                  · {{ (ruleStatsItems.length || ruleStats?.count || 0) }} 条
                  · 启用 {{ ruleStatsItems.filter(r => r.enabled !== false).length || ruleStats?.enabled || 0 }}
                </span>
              </div>
              <div class="chip-row">
                <button type="button" class="chip-btn" :class="{ on: settingsRulesFilter === 'all' }" @click="settingsRulesFilter = 'all'">全部</button>
                <button type="button" class="chip-btn" :class="{ on: settingsRulesFilter === 'sensor' }" @click="settingsRulesFilter = 'sensor'">内置传感器</button>
                <button type="button" class="chip-btn" :class="{ on: settingsRulesFilter === 'custom' }" @click="settingsRulesFilter = 'custom'">快照规则</button>
                <button type="button" class="chip-btn" @click="loadSettings(); loadRules()">刷新</button>
              </div>
            </div>
            <div class="table-scroll settings-rules-table">
              <table>
                <thead>
                  <tr>
                    <th>启用</th>
                    <th>标题</th>
                    <th>来源</th>
                    <th>级别</th>
                    <th>类型 / 关键字</th>
                    <th>说明</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="r in filteredSettingsRules" :key="r.id">
                    <td>
                      <label class="switch">
                        <input type="checkbox" :checked="r.enabled !== false" @change="toggleRule(r, $event.target.checked)" />
                        <i />
                      </label>
                    </td>
                    <td>
                      <b class="strong">{{ r.title }}</b>
                      <div class="meta">{{ r.id }}</div>
                    </td>
                    <td>
                      <span class="pill" :class="{ on: r.builtin || r.source === 'sensor' }">
                        {{ (r.builtin || r.source === 'sensor') ? '内置传感器' : '快照规则' }}
                      </span>
                    </td>
                    <td><span class="sev" :data-s="r.severity">{{ sevLabel(r.severity) }}</span></td>
                    <td class="muted">
                      <template v-if="r.builtin || r.source === 'sensor'">
                        {{ r.etype || '—' }}
                        <span v-if="r.summary_contains"> · {{ r.summary_contains }}</span>
                      </template>
                      <template v-else>
                        {{ (r.modules || []).map(modLabel).join('、') || '—' }}
                        <span v-if="(r.patterns || []).length"> · {{ (r.patterns || []).length }} 特征</span>
                      </template>
                    </td>
                    <td class="muted" :title="r.note">{{ r.note || '—' }}</td>
                  </tr>
                </tbody>
              </table>
              <p v-if="!filteredSettingsRules.length" class="empty settings-rules-empty">暂无规则数据，请点右上角「刷新」或前往规则管理</p>
            </div>
          </div>
        </div>
      </section>

      <!-- ========== 账号管理 ========== -->
      <section v-else-if="page === 'accounts'" class="page">
        <header class="page-hd">
          <div>
            <h1>账号管理</h1>
            <p class="desc">EDR 后台独立账号，与分析平台账号互不相通</p>
          </div>
          <div class="hd-right">
            <button type="button" class="btn primary" @click="openUserForm()">新建账号</button>
          </div>
        </header>
        <div class="panel pad">
          <div v-if="edrUsers.length" class="table-scroll">
          <table class="acct-table">
            <thead>
              <tr><th>账号</th><th>角色</th><th>状态</th><th>最近登录</th><th>操作</th></tr>
            </thead>
            <tbody>
              <tr v-for="u in edrUsers" :key="u.id">
                <td>
                  <div class="acct-name">
                    <span class="ru-avatar sm">{{ (u.display_name || u.username || '?').slice(0, 1).toUpperCase() }}</span>
                    <div>
                      <strong>{{ u.display_name || u.username }}</strong>
                      <small>{{ u.username }}<i v-if="u.id === user?.id" class="acct-me">我</i></small>
                    </div>
                  </div>
                </td>
                <td>
                  <select class="field sm" :value="u.role" :disabled="u.id === user?.id" @change="changeUserRole(u, $event.target.value)">
                    <option v-for="(lb, k) in roleLabels" :key="k" :value="k">{{ lb }}</option>
                  </select>
                </td>
                <td>
                  <span class="pill" :class="{ on: u.enabled }">{{ u.enabled ? '启用' : '已禁用' }}</span>
                  <span v-if="u.must_change" class="pill warn">待改密</span>
                </td>
                <td class="muted">
                  {{ u.last_login_at ? fmtEpoch(u.last_login_at) : '从未登录' }}
                  <small v-if="u.last_login_ip" class="acct-ip">{{ u.last_login_ip }}</small>
                </td>
                <td class="ops">
                  <template v-if="u.id !== user?.id">
                    <button type="button" class="btn-text" @click="toggleUserEnabled(u)">{{ u.enabled ? '禁用' : '启用' }}</button>
                    <button type="button" class="btn-text" @click="openResetPw(u)">重置密码</button>
                    <button type="button" class="btn-text" style="color:var(--danger)" @click="removeUser(u)">删除</button>
                  </template>
                  <button v-else type="button" class="btn-text" @click="openPwDialog">修改密码</button>
                </td>
              </tr>
            </tbody>
          </table>
          </div>
          <p v-else class="empty">暂无账号</p>
          <p class="hint">角色说明：管理员可处置终端、改规则与配置、管理账号；分析员与只读账号仅可查看。</p>
        </div>
      </section>

      <!-- ========== 通知渠道 ========== -->
      <section v-else-if="page === 'notify'" class="page">
        <header class="page-hd">
          <div>
            <h1>通知渠道</h1>
            <p class="desc">新威胁事件达到级别阈值时推送（同主机同标题 10 分钟内只推一次）</p>
          </div>
        </header>
        <div class="panel pad settings">
          <label class="chk"><input type="checkbox" v-model="notifyForm.enabled" /> 启用通知</label>
          <label>
            <span>最低级别</span>
            <select v-model="notifyForm.min_severity" class="field">
              <option value="medium">中及以上</option>
              <option value="high">高及以上</option>
              <option value="critical">仅严重</option>
            </select>
          </label>
          <label>
            <span>通用 Webhook（POST JSON）</span>
            <input v-model="notifyForm.webhook_url" class="field" placeholder="https://example.com/edr-hook" />
          </label>
          <label>
            <span>飞书机器人 Webhook</span>
            <input v-model="notifyForm.feishu_webhook" class="field" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..." />
          </label>
          <label>
            <span>钉钉机器人 Webhook</span>
            <input v-model="notifyForm.dingtalk_webhook" class="field" placeholder="https://oapi.dingtalk.com/robot/send?access_token=..." />
          </label>
          <label>
            <span>钉钉加签密钥（可选）</span>
            <input v-model="notifyForm.dingtalk_secret" class="field" type="password" placeholder="SEC..." />
          </label>
          <div class="row">
            <button type="button" class="btn primary" :disabled="saving" @click="saveNotify">保存</button>
            <button type="button" class="btn" @click="doTestNotify">发送测试消息</button>
          </div>
          <div v-if="notifyTestResult" class="notify-results">
            <p v-if="notifyTestResult.error" class="err-text">{{ notifyTestResult.error }}</p>
            <p v-for="r in notifyTestResult.results || []" :key="r.channel" :class="r.ok ? 'hint' : 'err-text'">
              {{ ({ webhook: 'Webhook', feishu: '飞书', dingtalk: '钉钉' })[r.channel] || r.channel }}：
              {{ r.ok ? `成功（HTTP ${r.status}）` : `失败：${r.error}` }}
            </p>
          </div>
        </div>
      </section>

      <!-- ========== 存储与保留 ========== -->
      <section v-else-if="page === 'storage'" class="page">
        <header class="page-hd">
          <div>
            <h1>存储与保留</h1>
            <p class="desc">SQLite 存近期热数据；MySQL 双写保留 4 倍时长作历史检索层；保留期在「EDR 策略」中设置</p>
          </div>
          <button type="button" class="btn" @click="loadStorage">刷新</button>
        </header>
        <div class="host-summary" v-if="storeInfo">
          <div class="hs"><span>SQLite 时间线</span><b>{{ fmtNum(storeInfo.sqlite_timeline) }}</b></div>
          <div class="hs"><span>SQLite 事件</span><b>{{ fmtNum(storeInfo.sqlite_events) }}</b></div>
          <div class="hs on"><span>MySQL 时间线</span><b>{{ storeInfo.mysql?.available ? fmtNum(storeInfo.mysql.timeline) : '不可用' }}</b></div>
          <div class="hs on"><span>MySQL 事件</span><b>{{ storeInfo.mysql?.available ? fmtNum(storeInfo.mysql.events) : '不可用' }}</b></div>
        </div>
        <div class="panel pad" v-if="storeInfo">
          <p>
            时间线保留 <b>{{ storeInfo.retention?.timeline_days }}</b> 天 ·
            已关闭事件保留 <b>{{ storeInfo.retention?.events_days }}</b> 天 ·
            MySQL 双写 <b>{{ storeInfo.retention?.mysql_dual_write ? '开' : '关' }}</b>
          </p>
          <p class="hint">后台每小时自动清理一次；未关闭的威胁事件永不清理。</p>
          <button type="button" class="btn danger-outline" @click="doPurge">立即按保留期清理</button>
        </div>
        <div class="panel pad" style="margin-top:14px">
          <h3>历史时间线检索（MySQL）</h3>
          <div class="hunt-bar">
            <input v-model="storeQ" class="search grow" placeholder="关键字：进程名 / IP / 路径…" @keyup.enter="doStoreSearch" />
            <button type="button" class="btn primary" @click="doStoreSearch">检索</button>
          </div>
          <table v-if="storeHits.length" style="margin-top:12px">
            <thead><tr><th>时间</th><th>主机</th><th>类型</th><th>摘要</th></tr></thead>
            <tbody>
              <tr v-for="(h, i) in storeHits" :key="i">
                <td>{{ fmtTime(h.ts) }}</td>
                <td>{{ h.hostname || short(h.agent_id) }}</td>
                <td class="mono">{{ h.etype }}</td>
                <td>{{ h.summary }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- ========== EDR 策略 ========== -->
      <section v-else-if="page === 'policy'" class="page">
        <header class="page-hd">
          <div>
            <h1>EDR 策略</h1>
            <p class="desc">热更新采集周期、处置开关、时间线；白名单降低误报（rev {{ policyRev }}）</p>
          </div>
          <button type="button" class="btn primary" :disabled="saving" @click="savePolicy">保存策略</button>
        </header>
        <div class="ov-grid" style="min-height:auto">
          <div class="panel pad settings">
            <h3 style="margin:0 0 12px">全局策略</h3>
            <label class="chk"><input type="checkbox" v-model="policyForm.response_enabled" /> 允许远程处置</label>
            <label class="chk"><input type="checkbox" v-model="policyForm.remote_ops_enabled" /> 允许远程运维（读注册表/文件/命令/Shell）</label>
            <label class="chk"><input type="checkbox" v-model="policyForm.remote_ops_read_only" /> 远程运维只读（禁止 run_cmd；Shell 仅允许 dir/ipconfig 等调查命令）</label>
            <label class="chk"><input type="checkbox" v-model="policyForm.remote_ops_run_cmd" /> 允许白名单命令（run_cmd）</label>
            <label class="chk"><input type="checkbox" v-model="policyForm.remote_ops_shell" /> 允许交互式 Shell 会话</label>
            <label class="chk"><input type="checkbox" v-model="policyForm.timeline_process" /> 上报进程时间线</label>
            <label class="chk"><input type="checkbox" v-model="policyForm.timeline_file" /> 上报文件时间线</label>
            <label class="chk"><input type="checkbox" v-model="policyForm.timeline_network" /> 上报网络外联时间线</label>
            <label class="chk"><input type="checkbox" v-model="policyForm.self_protect" /> 自保护（忽略普通 net stop + 收紧状态目录）</label>
            <label class="chk"><input type="checkbox" v-model="policyForm.fim_enabled" /> 文件完整性监控（hosts / 计划任务 / 启动目录 / System32 / 驱动 / 公共目录）</label>
            <label v-if="policyForm.fim_enabled">
              <span>FIM 自定义目录（每行一个，末尾加 <code>|r</code> 表示递归）</span>
              <textarea v-model="policyForm.fim_paths_text" class="field" rows="3" placeholder="D:\app\bin&#10;D:\web\wwwroot|r" />
            </label>
            <label>
              <span>定向日志 tail（<code>log_tail_paths</code>，非 Filebeat filestream）</span>
              <textarea v-model="policyForm.log_tail_paths_text" class="field mono" rows="2" placeholder="C:\ProgramData\YourApp\app.log" />
              <p class="hint sm">每行一个<strong>文件</strong>绝对路径，最多 20 条；写入时间线 <code>log_tail_line</code>。</p>
            </label>
            <label>
              <span>Winlog 通道模式</span>
              <select v-model="policyForm.winevent_channel_mode" class="field">
                <option value="all">全部通道</option>
                <option value="critical">critical 默认集</option>
                <option value="high_sens">高敏（critical + BITS/AppLocker/…）</option>
                <option value="custom">自定义列表</option>
              </select>
            </label>
            <label v-if="policyForm.winevent_channel_mode === 'custom' || policyForm.winevent_channel_mode === 'critical' || policyForm.winevent_channel_mode === 'high_sens'">
              <span>Winlog 通道 ID（每行一个；critical/high_sens 下为追加）</span>
              <textarea v-model="policyForm.winevent_channels_text" class="field mono" rows="2" placeholder="firewall&#10;bits&#10;applocker" />
            </label>
            <label>
              <span>心跳间隔（秒）</span>
              <input v-model.number="policyForm.heartbeat_sec" type="number" min="3" max="120" class="field" />
            </label>
            <label>
              <span>进程采集周期（秒）</span>
              <input v-model.number="policyForm.intervals_sec.process" type="number" min="3" max="300" class="field" />
            </label>
            <label>
              <span>网络采集周期（秒）</span>
              <input v-model.number="policyForm.intervals_sec.network" type="number" min="3" max="300" class="field" />
            </label>
            <label>
              <span>文件采集周期（秒）</span>
              <input v-model.number="policyForm.intervals_sec.file" type="number" min="5" max="600" class="field" />
            </label>
            <label>
              <span>时间线保留（天）</span>
              <input v-model.number="policyForm.timeline_retain_days" type="number" min="1" max="365" class="field" />
            </label>
            <label>
              <span>已关闭事件保留（天）</span>
              <input v-model.number="policyForm.events_retain_days" type="number" min="7" max="730" class="field" />
            </label>
            <label class="chk"><input type="checkbox" v-model="policyForm.mysql_dual_write" /> MySQL 双写（历史检索层）</label>
          </div>
          <div class="panel pad settings">
            <h3 style="margin:0 0 4px">告警加白</h3>
            <p class="muted" style="margin:0 0 10px;font-size:12px">
              命中的告警不再产生（所有检测来源统一生效）。值支持 * 通配；路径、注册表键以 \ 结尾表示整个目录 / 子键。也可在威胁事件里直接点「加白」。
            </p>
            <div class="hunt-bar">
              <select v-model="wlKind" class="search sev-filter">
                <option v-for="(lb, k) in ALLOW_KIND_LABELS" :key="k" :value="k">{{ lb }}</option>
              </select>
              <input v-model="wlValue" class="search grow" placeholder="匹配值，如 C:\Tools\*.exe" />
              <input v-model="wlRule" class="search" style="max-width:200px" placeholder="限定告警标题（可选，支持 *）" />
              <input v-model="wlNote" class="search" style="max-width:160px" placeholder="备注" />
              <button type="button" class="btn" @click="addWl">添加</button>
            </div>
            <table v-if="whitelist.length" style="margin-top:12px">
              <thead><tr><th>类型</th><th>值</th><th>限定告警</th><th>范围</th><th>命中</th><th>最近命中</th><th>备注</th><th>状态</th><th></th></tr></thead>
              <tbody>
                <tr v-for="w in whitelist" :key="w.id" :class="{ 'wl-off': !w.enabled }">
                  <td>{{ ALLOW_KIND_LABELS[w.kind] || w.kind }}</td>
                  <td class="mono wl-val" :title="w.value">{{ w.value }}</td>
                  <td class="wl-val" :title="w.rule">{{ w.rule || '全部' }}</td>
                  <td>{{ w.agent_id ? agentLabel(w.agent_id) : '全部终端' }}</td>
                  <td>{{ w.hits || 0 }}</td>
                  <td>{{ w.last_hit_at ? fmtTime(w.last_hit_at) : '—' }}</td>
                  <td>{{ w.note || '—' }}</td>
                  <td>
                    <button type="button" class="btn-text" @click="toggleWl(w)">{{ w.enabled ? '启用中' : '已停用' }}</button>
                  </td>
                  <td><button type="button" class="btn-text" style="color:var(--danger)" @click="delWl(w.id)">删除</button></td>
                </tr>
              </tbody>
            </table>
            <p v-else class="empty sm">暂无加白条目</p>
          </div>
          <div class="panel pad settings">
            <h3 style="margin:0 0 6px">终端生效情况（rev {{ policyRollout?.rev ?? policyRev }}）</h3>
            <p class="muted" style="margin:0 0 10px;font-size:12px">终端先整体校验再生效，试用 60 秒通过后记为 LKG；试用期资源超限或反复重启会自动回滚到上一个 LKG。</p>
            <div v-if="policyRollout" class="health-chips">
              <span class="hchip">已生效 {{ policyRollout.summary.applied }}</span>
              <span class="hchip">试用中 {{ policyRollout.summary.probation }}</span>
              <span class="hchip">待生效 {{ policyRollout.summary.pending }}</span>
              <span class="hchip" :class="{ warn: policyRollout.summary.rejected }">已拒绝 {{ policyRollout.summary.rejected }}</span>
              <span class="hchip" :class="{ warn: policyRollout.summary.rolled_back }">已回滚 {{ policyRollout.summary.rolled_back }}</span>
              <span class="hchip">旧版不回报 {{ policyRollout.summary.legacy }}</span>
            </div>
            <table v-if="policyRollout?.problems?.length" style="margin-top:10px">
              <thead><tr><th>主机</th><th>状态</th><th>当前生效</th><th>原因</th></tr></thead>
              <tbody>
                <tr v-for="p in policyRollout.problems" :key="p.agent_id">
                  <td>{{ p.hostname || short(p.agent_id) }}</td>
                  <td>{{ POLICY_STATUS_LABELS[p.status] || p.status }}</td>
                  <td>rev {{ p.applied_rev || '默认' }}</td>
                  <td class="muted">{{ p.error || '—' }}</td>
                </tr>
              </tbody>
            </table>
            <h3 style="margin:16px 0 8px">版本历史</h3>
            <table v-if="policyHistory.length">
              <thead><tr><th>rev</th><th>时间</th><th>操作人</th><th>说明</th><th></th></tr></thead>
              <tbody>
                <tr v-for="h in policyHistory" :key="h.rev">
                  <td class="mono">{{ h.rev }}<em v-if="h.rev === policyRev" class="pill on" style="margin-left:4px">当前</em></td>
                  <td class="muted">{{ fmtTime(h.created_at) }}</td>
                  <td>{{ h.actor || '—' }}</td>
                  <td class="muted">{{ h.note || '—' }}</td>
                  <td>
                    <button v-if="isAdmin && h.rev !== policyRev" type="button" class="btn-text" @click="doPolicyRollback(h.rev)">回滚到此版本</button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p v-else class="empty sm">暂无历史版本</p>
          </div>
        </div>
      </section>
    </div>

    <!-- 告警加白 -->
    <div v-if="allowDlg" class="dlg-mask" @click.self="allowDlg = null">
      <form class="dlg allow-dlg" @submit.prevent="submitAllow">
        <h3>加白：以后不再对它告警</h3>
        <p class="allow-src">{{ allowDlg.title }}</p>
        <p v-if="allowDlg.loading" class="hint">读取告警对象…</p>
        <template v-else>
          <div class="allow-sec-row">
            <span class="allow-sec">按什么加白</span>
            <button type="button" class="btn sm" @click.prevent="allowPickAll">全选</button>
            <button type="button" class="btn sm" @click.prevent="allowPickClear">清空</button>
          </div>
          <p class="hint sm">可多选；确认后将创建多条加白规则（每条维度一条）</p>
          <div class="allow-opts">
            <label v-for="(c, i) in allowDlg.items" :key="i" class="allow-opt" :class="{ on: allowDlg.picks.includes(i) }">
              <input type="checkbox" :checked="allowDlg.picks.includes(i)" @change="toggleAllowPick(i)" />
              <span class="allow-k">{{ c.label }}</span>
              <code :title="c.value">{{ c.value }}</code>
            </label>
          </div>
          <label v-if="allowDlg.picks.length <= 1">
            <span>匹配值 <em class="allow-tip">可改；支持 * 通配，路径/注册表以 \ 结尾表示整个目录</em></span>
            <input v-model="allowDlg.value" class="field mono" />
          </label>
          <p v-else class="hint sm">已选 {{ allowDlg.picks.length }} 条，将分别使用各自候选值加白（取消不需要的勾选项即可）</p>
          <label v-if="allowDlg.rulePrefix && allowDlgHasNonTitlePick" class="chk">
            <input type="checkbox" v-model="allowDlg.limitRule" />
            仅对「{{ allowDlg.rulePrefix }}」这类告警生效（推荐，避免放过该对象的其他可疑行为）
          </label>
          <label>
            <span>生效范围</span>
            <select v-model="allowDlg.scope" class="field">
              <option value="host">仅此终端（{{ allowDlg.hostname || short(allowDlg.agentId) }}）</option>
              <option value="all">全部终端</option>
            </select>
          </label>
          <label><span>备注</span><input v-model="allowDlg.note" class="field" placeholder="如：运维巡检脚本，已确认正常" /></label>
          <label class="chk"><input type="checkbox" v-model="allowDlg.applyExisting" /> 同时把已有的同类未处置告警标为「无需处置」</label>
          <p v-if="allowDlg.rulePrefix && /注册表|FIM|持久化/.test(allowDlg.title || '')" class="hint sm warn-hint">
            注册表/FIM 类告警：每条标题往往只对应一个子项（如 sysdiag、SecurityHealth）。若只加白单条注册表键，其它子项仍会告警；建议勾选「同类告警（标题通配）」或「整类监控标签 FIM扩展\」。
          </p>
          <p v-if="allowDlg.kind === 'title' && /^\*|\*$/.test(allowDlg.value) && allowDlg.scope === 'all'" class="hint warn-hint">
            按标题通配且对全部终端生效，范围较大，请确认。
          </p>
        </template>
        <p v-if="allowDlg.err" class="dlg-err">{{ allowDlg.err }}</p>
        <div class="dlg-ops">
          <button type="button" class="btn" @click="allowDlg = null">取消</button>
          <button type="submit" class="btn primary" :disabled="allowDlg.busy || allowDlg.loading || !allowSubmitReady">
            {{ allowDlg.busy ? '提交中…' : (allowDlg.picks.length > 1 ? `确认加白 (${allowDlg.picks.length})` : '确认加白') }}
          </button>
        </div>
      </form>
    </div>

    <!-- 账号相关弹窗：修改本人密码 / 新建账号 / 重置他人密码 -->
    <div v-if="dlg" class="dlg-mask" @click.self="dlg = ''">
      <form class="dlg" @submit.prevent="submitDlg">
        <h3>{{ dlgTitle }}</h3>
        <template v-if="dlg === 'pw'">
          <label><span>当前密码</span><input v-model="dlgForm.current" type="password" class="field" autocomplete="current-password" /></label>
          <label><span>新密码</span><input v-model="dlgForm.password" type="password" class="field" autocomplete="new-password" placeholder="至少 8 位，含字母 / 数字 / 符号中两类" /></label>
          <label><span>确认新密码</span><input v-model="dlgForm.password2" type="password" class="field" autocomplete="new-password" /></label>
          <p class="hint">修改后，你在其他浏览器上的登录会被强制下线。</p>
        </template>
        <template v-else-if="dlg === 'create'">
          <label><span>用户名</span><input v-model.trim="dlgForm.username" class="field" placeholder="字母、数字或 _ . - @" /></label>
          <label><span>显示名（可选）</span><input v-model.trim="dlgForm.display_name" class="field" /></label>
          <label>
            <span>角色</span>
            <select v-model="dlgForm.role" class="field">
              <option v-for="(lb, k) in roleLabels" :key="k" :value="k">{{ lb }}</option>
            </select>
          </label>
          <label><span>初始密码</span><input v-model="dlgForm.password" type="password" class="field" autocomplete="new-password" placeholder="至少 8 位，含字母 / 数字 / 符号中两类" /></label>
          <p class="hint">对方首次登录时需要自行修改密码。</p>
        </template>
        <template v-else-if="dlg === 'reset'">
          <p class="hint">为 <b>{{ dlgForm.target?.username }}</b> 设置临时密码，对方登录后需立即修改；其现有登录会被下线。</p>
          <label><span>临时密码</span><input v-model="dlgForm.password" type="password" class="field" autocomplete="new-password" /></label>
        </template>
        <p v-if="dlgError" class="dlg-err">{{ dlgError }}</p>
        <div class="dlg-ops">
          <button type="button" class="btn" @click="dlg = ''">取消</button>
          <button type="submit" class="btn primary" :disabled="dlgBusy">{{ dlgBusy ? '提交中…' : '确定' }}</button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup>
import { computed, defineComponent, h, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import {
  agentProtocol, agentRuleStats, addIoc, addWhitelist, attackStory, attckBoard,
  bulkAgentRulesEnabled, bulkElasticEvmEnabled, getElasticDetectionRuleDetail,
  createAgentCommand, createAgentRule,
  deleteAgent, deleteAgentRule, deleteEvent, deleteIoc, deleteUpgradePackage, deleteWhitelist,
  eventAllowCandidates, setWhitelistEnabled, deleteEventsBulk,
  downloadInstallPackage, getAgentRelease, buildAgentRelease, getAgentSyncManifest, bumpAgentSync,
  getAgentIntegrations, saveAgentIntegrations, getMemoryYaraRules, saveMemoryYaraControls,
  getAgentCredentials, setSharedKeyPolicy, revokeAgent, getProcessEntity, huntDns,
  getPolicyHistory, getPolicyRollout, rollbackPolicy,
  getAgentPolicy, getAgentTags, getEvent, enrichEventDetail, getNotifyConfig, getSnapshot, huntAgents, importIoc, iocLibStatus,
  listProcessEntities,
  investigateLogDetail, investigateLogs, threatProcessTree,
  setNotifyConfig, storePurge, storeSearch, storeStats, testNotify,
  listAgentAudit, listAgentCommands, listAllAgentCommands, listAgentGroups, listAgents, listEvents, listIoc,
  listSeqRules, listTimeline, listUpgradePackages, listWhitelist, patchAgentRule, pushUpgradePackage,
  getEdrOverview, enrichEventDetails, getFleetDrift, downloadAgentDiagnostics, listAgentDiagnostics, getRelatedEvents,
  setAgentPolicy, setAgentTags,
  subscribeAgentStream, updateAgentRule, uploadUpgradePackage, upsertAgentGroup, upsertSeqRule, deleteSeqRule,
  edrChangePassword, edrCreateUser, edrDeleteUser, edrGetSettings, edrListUsers, edrResetPassword,
  edrSaveSettings, edrUpdateUser, rotateEnrollKey,
  aiStatus, aiSetupLocal, aiListSkills, aiListHosts, aiAnalyzeHost,
} from './api'

const props = defineProps({ user: { type: Object, default: null } })
const emit = defineEmits(['logout', 'user-updated'])
const isAdmin = computed(() => props.user?.role === 'admin')
const userInitial = computed(() => String(props.user?.display_name || props.user?.username || '?').slice(0, 1).toUpperCase())
const userMenuOpen = ref(false)

const LABELS = {
  sysinfo: '系统', process: '进程', service: '服务', task: '计划任务',
  startup: '启动项', network: '网络', listen: '监听端口',
  software: '已装软件', hotfix: '补丁', file: '文件', user: '用户', driver: '驱动',
  browser: '浏览器记录',
}
const HOST_TAB_GROUPS = [
  { id: 'runtime', label: '运行态', mods: ['process', 'network', 'service', 'task', 'startup', 'file'] },
  { id: 'inventory', label: '资产清单', mods: ['software', 'hotfix', 'driver', 'listen', 'user', 'sysinfo', 'browser'] },
  { id: 'remote', label: '远程管理', mods: [] },
]
const HOST_REMOTE_TABS = [
  { id: 'ops', label: '应急处置', hint: '隔离 / 杀进程 / 指令审计' },
  { id: 'livequery', label: 'Live Query', hint: 'Osquery 式只读表' },
  { id: 'files', label: '文件浏览', hint: '只读列目录与读文件' },
  { id: 'reg', label: '注册表', hint: '只读查询键值' },
  { id: 'cmd', label: '白名单命令', hint: '单条 cmd，带白名单校验' },
  { id: 'shell', label: '交互 Shell', hint: 'cmd 会话，轮询输出' },
]
const LIVE_QUERY_TABLES_DEFAULT = [
  { name: 'processes', osquery_analog: 'processes' },
  { name: 'services', osquery_analog: 'services' },
  { name: 'listening_ports', osquery_analog: 'listening_ports' },
  { name: 'scheduled_tasks', osquery_analog: 'scheduled_tasks' },
  { name: 'startup_items', osquery_analog: 'startup_items' },
  { name: 'users', osquery_analog: 'users' },
  { name: 'network_connections', osquery_analog: 'process_open_sockets' },
  { name: 'drivers', osquery_analog: 'drivers' },
  { name: 'installed_software', osquery_analog: 'programs' },
  { name: 'hotfixes', osquery_analog: 'patches' },
]
const HOST_SHELL_QUICK = ['ipconfig', 'whoami', 'systeminfo', 'tasklist', 'dir', 'netstat -ano']
const HOST_REG_SHORTCUTS = [
  { label: 'Run', hive: 'HKLM', key: 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' },
  { label: 'RunOnce', hive: 'HKLM', key: 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' },
  { label: 'IFEO', hive: 'HKLM', key: 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' },
  { label: 'Services', hive: 'HKLM', key: 'SYSTEM\\CurrentControlSet\\Services' },
]
const FILE_EXT_OPTIONS = [
  'exe', 'dll', 'sys', 'scr', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'msi', 'jar',
  'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'hta', 'lnk',
]
const RULE_TEMPLATES = [
  {
    id: 'ps-enc',
    label: 'PS 编码执行',
    title: 'PowerShell 编码执行',
    severity: 'high',
    modules: ['process', 'task', 'startup'],
    fieldsText: 'command_line,command,path',
    patternsText: '-enc \n-encodedcommand\nfrombase64string',
    fileExts: ['exe', 'ps1'],
    match: 'substring',
    note: '命令行含编码执行特征',
  },
  {
    id: 'temp-exe',
    label: '临时目录 EXE',
    title: '临时目录可执行文件',
    severity: 'high',
    modules: ['process', 'service', 'startup', 'file'],
    fieldsText: 'path,command,command_line,name',
    patternsText: '\\temp\\\n\\tmp\\\n\\appdata\\local\\temp\\',
    fileExts: ['exe', 'dll', 'scr', 'bat', 'cmd', 'ps1'],
    match: 'substring',
    note: '路径落在临时目录且为可执行类文件',
  },
  {
    id: 'office-macro',
    label: 'Office 宏链',
    title: 'Office 衍生脚本解释器',
    severity: 'high',
    modules: ['process'],
    fieldsText: 'parent_name,name,command_line,path',
    patternsText: 'winword.exe\nexcel.exe\npowerpnt.exe',
    fileExts: ['exe'],
    match: 'substring',
    note: '结合父进程研判；建议配合行为序列',
  },
  {
    id: 'lolbin',
    label: 'LOLBin 下载',
    title: '可疑下载器 / LOLBin',
    severity: 'high',
    modules: ['process', 'task', 'startup'],
    fieldsText: 'name,command_line,command,path',
    patternsText: 'certutil\nbitsadmin\ninvoke-webrequest\niwr \nwget \ncurl ',
    fileExts: ['exe', 'bat', 'cmd', 'ps1'],
    match: 'substring',
    note: '',
  },
  {
    id: 'script-file',
    label: '脚本落地',
    title: '可疑脚本文件',
    severity: 'medium',
    modules: ['file'],
    fieldsText: 'name,path,directory,ext',
    patternsText: '\\users\\\n\\appdata\\\n\\temp\\',
    fileExts: ['ps1', 'vbs', 'js', 'bat', 'cmd', 'hta'],
    match: 'substring',
    note: '用户目录下的脚本类文件',
  },
  {
    id: 'unsigned',
    label: '未签名文件',
    title: '未签名可执行文件',
    severity: 'medium',
    modules: ['process', 'file', 'startup'],
    fieldsText: 'path,name,signed',
    patternsText: '',
    fileExts: ['exe', 'dll', 'sys', 'scr'],
    signedFilter: 'unsigned',
    match: 'substring',
    note: '签名非 Valid',
  },
  {
    id: 'root-drop',
    label: '根目录投放',
    title: '磁盘根目录投放可执行文件',
    severity: 'high',
    modules: ['file', 'process'],
    fieldsText: 'path',
    patternsText: '^[A-Za-z]:\\\\[^\\\\]+\\.(exe|dll|bat|cmd|ps1|scr)$',
    fileExts: ['exe', 'dll', 'bat', 'cmd', 'ps1', 'scr'],
    match: 'regex',
    note: '如 C:\\evil.exe',
  },
  {
    id: 'dir-unsigned-drop',
    label: '目录新建未签名',
    title: '指定目录新建未签名文件',
    severity: 'high',
    modules: ['file'],
    fieldsText: 'path,name,signed',
    patternsText: '*',
    fileExts: ['exe', 'dll', 'sys', 'scr'],
    signedFilter: 'unsigned',
    pathPrefixes: ['D:\\Tools\\'],
    match: 'substring',
    note: '路径前缀改成要监控的目录；保存后 Agent 自动对该目录挂 FIM 实时监控（盘符根只监控一层）',
  },
]
const SEQ_TEMPLATES = [
  {
    id: 'office-ps',
    label: 'Office → PS',
    title: '办公进程后出现 PowerShell',
    severity: 'high',
    window_sec: 180,
    note: '宏/钓鱼常见链 · T1566→T1059',
    steps: [
      { etype_contains: 'process', summary_contains: '', name_regex: '(?i)(winword|excel|powerpnt|outlook)\\.exe' },
      { etype_contains: 'process', summary_contains: '', name_regex: '(?i)(powershell|pwsh|cmd)\\.exe' },
    ],
  },
  {
    id: 'temp-net',
    label: '临时进程 → 外联',
    title: '临时目录进程后外联',
    severity: 'high',
    window_sec: 120,
    note: '落地执行后外联 · T1105→T1071',
    steps: [
      { etype_contains: 'process', summary_contains: '临时', name_regex: '' },
      { etype_contains: 'network', summary_contains: '', name_regex: '' },
    ],
  },
  {
    id: 'file-proc',
    label: '文件 → 进程',
    title: '文件落地后进程创建',
    severity: 'medium',
    window_sec: 120,
    note: '投放后执行 · T1105→T1204',
    steps: [
      { etype_contains: 'file', summary_contains: '', name_regex: '' },
      { etype_contains: 'process', summary_contains: '', name_regex: '' },
    ],
  },
]
const FIELD_BY_MODULE = {
  process: ['name', 'path', 'command_line', 'user', 'parent_name', 'sha256'],
  service: ['name', 'display_name', 'path', 'account'],
  task: ['task_name', 'command', 'path', 'execute'],
  startup: ['name', 'command', 'path', 'location'],
  network: ['local', 'remote', 'state', 'proto'],
  sysinfo: ['hostname', 'caption'],
  file: ['name', 'path', 'directory', 'ext'],
  user: ['name', 'session', 'state'],
}
const COL_LABELS = {
  name: '名称', display_name: '显示名', status: '状态', path: '路径',
  pid: 'PID', ppid: '父PID', command: '命令', command_line: '命令行',
  task_name: '任务名', author: '作者', next_run: '下次运行', last_run: '上次运行',
  last_result: '上次结果', working_directory: '工作目录', execute: '执行程序', arguments: '参数',
  triggers: '触发器', description: '描述', account: '运行账户', start_type: '启动类型',
  exit_code: '退出码', user: '用户', session_id: '会话', create_time: '创建时间',
  memory_mb: '内存(MB)', handles: '句柄数',
  local: '本地', remote: '远程', proto: '协议', state: '连接状态',
  location: '位置', caption: '系统', hostname: '主机名', domain: '域',
  agent_ver: 'Agent 版本', build: '内部版本', collected_at: '采集时间',
  goarch: '架构', goos: '操作系统',
  ext: '扩展名', size: '大小(字节)', size_kb: '大小(KB)', modified: '修改时间',
  created: '创建时间', directory: '所在目录', session: '会话名',
  enabled: '启用', last_logon: '上次登录', password_required: '需密码',
  principal: 'SID', source: '来源', manufacturer: '厂商', model: '型号',
  total_ram_mb: '内存(MB)', last_boot: '上次开机', install_date: '安装日期',
  version: '版本', ip: 'IP', num_cpu: 'CPU 核数', os_family: '系统族',
  parent_name: '父进程', parent_path: '父路径', uptime: '运行时长', uptime_sec: '运行秒数',
  signed: '签名状态', signer: '签名者', sha256: 'SHA256', company: '公司名',
  file_version: '文件版本', process_name: '进程名',
  risk_score: '风险分', risk_tags: '风险标签', noise: '系统噪声',
  module_count: '模块总数', module_third_count: '第三方DLL', modules_summary: '已加载DLL',
  modules: '模块列表',
  publisher: '发布者', arch: '位数', install_path: '安装路径', uninstall: '卸载命令',
  kb: '补丁号', installed_on: '安装时间', installed_by: '安装者', inventory: '清单类型',
  process_guid: '进程GUID', parent_guid: '父进程GUID', elevated: '已提权', integrity: '完整性级别',
  script_block: '脚本块', payload: '载荷',
  module: '模块', module_name: '模块名', host_process: '宿主进程', process_path: '进程路径',
  image: '映像路径',
  hive: 'Hive', key: '完整路径', reg_key: '注册表键', value_name: '值名', value: '写入值', old_value: '原值',
  value_type: '值类型', change: '变更类型', label: '监控点', category: '类别', watch: '监控规则', user_sid: '用户 SID',
  etype: '事件类型', event_id: '事件 ID', channel: '日志通道', script_block_id: '脚本块 ID',
  target_path: '目标进程', target_pid: '目标 PID', access: '访问权限', start_address: '起始地址', call_trace: '调用栈',
  member: '成员', group: '组', by: '操作者', logon_type: '登录类型', substatus: '子状态码', target: '目标服务器',
  privileges: '特权', process: '进程', task: '任务', content: '任务定义',
  ioc_value: '情报值', ioc_type: '情报类型', malware: '恶意家族', intel_source: '情报来源', matched_from: '匹配字段',
  trigger: '触发事件', lib: '情报库', ioc_id: '情报 ID',
  remote_ip: '远程 IP', remote_port: '远程端口', old_sha256: '原 SHA256', old_size: '原大小(字节)',
  query: '查询域名', qtype: '记录类型码', qtype_name: '记录类型', status_name: '解析结果', answers: '解析地址',
  cnames: 'CNAME', dga_score: 'DGA 分数', nx_count: '失败数', window_sec: '统计窗口(秒)', samples: '样本域名',
  entity_id: '进程实体', parent_create_time: '父进程创建时间', duration_sec: '存活(秒)', from: '原值', to: '新值',
}

const HostTable = defineComponent({
  name: 'HostTable',
  props: { rows: { type: Array, default: () => [] } },
  emits: ['view', 'remove'],
  setup(props, { emit }) {
    return () => h('div', { class: 'table-scroll' }, [
      h('table', [
        h('thead', [h('tr', ['主机', '系统', 'IP', '状态', '最近心跳', '版本', '操作'].map((t) => h('th', t)))]),
        h('tbody', (props.rows || []).map((a) => h('tr', [
          h('td', { class: 'strong' }, a.hostname || '—'),
          h('td', a.os_family || '—'),
          h('td', a.ip || '—'),
          h('td', [h('span', { class: ['pill', a.online ? 'on' : ''] }, a.online ? '在线' : '离线')]),
          h('td', a.last_seen || '—'),
          h('td', a.version || '—'),
          h('td', { class: 'ops' }, [
            h('button', { type: 'button', class: 'link', onClick: () => emit('view', a) }, '查看主机'),
            h('button', { type: 'button', class: 'link danger', onClick: () => emit('remove', a) }, '删除'),
          ]),
        ]))),
      ]),
      !(props.rows || []).length ? h('p', { class: 'empty' }, '暂无终端，请先下载安装包部署') : null,
    ])
  },
})

const I = {
  grid: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
  detect: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2"/></svg>',
  rules: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M8 6h13M8 12h13M8 18h13"/><circle cx="4" cy="6" r="1.2" fill="currentColor" stroke="none"/><circle cx="4" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="4" cy="18" r="1.2" fill="currentColor" stroke="none"/></svg>',
  asset: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="4" width="18" height="14" rx="2"/><path d="M8 20h8M12 18v2"/></svg>',
  deploy: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3v12M8 11l4 4 4-4"/><path d="M5 19h14"/></svg>',
  config: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
  ai: '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 3l2.2 4.5L19 9l-4.2 2.1L12 16l-2.8-4.9L5 9l4.8-1.5L12 3z"/><circle cx="12" cy="19" r="1.6"/></svg>',
}
const railItems = [
  { id: 'overview', label: '数据概览', short: '概览', ico: I.grid },
  { id: 'detect', label: '检测响应', short: '检测', ico: I.detect },
  { id: 'ai', label: 'AI 分析', short: 'AI', ico: I.ai },
  { id: 'rules', label: '规则管理', short: '规则', ico: I.rules },
  { id: 'asset', label: '终端资产', short: '资产', ico: I.asset },
  { id: 'deploy', label: '部署运营', short: '部署', ico: I.deploy },
  { id: 'config', label: '平台配置', short: '配置', ico: I.config },
]

const section = ref('overview')
const menuPinned = ref(false)
const menuHover = ref(false)
let menuLeaveTimer = null
const menuVisible = computed(() => menuPinned.value || menuHover.value)
function onNavEnter() {
  if (menuLeaveTimer) {
    clearTimeout(menuLeaveTimer)
    menuLeaveTimer = null
  }
  menuHover.value = true
}
function onNavLeave() {
  if (menuLeaveTimer) clearTimeout(menuLeaveTimer)
  menuLeaveTimer = setTimeout(() => {
    menuHover.value = false
    menuLeaveTimer = null
  }, 180)
}
const page = ref('overview')
/** 从威胁视图返回时回到「威胁事件」或「恶意文件」列表 */
const eventListReturnPage = ref('events')
const NAV_STORE_KEY = 'edr_admin_nav'
const NAV_PAGES = new Set([
  'overview', 'events', 'malware', 'behaviors', 'attck', 'investigate', 'timeline',
  'hunt', 'dns', 'ioc', 'rules', 'seq', 'hosts', 'groups', 'deploy', 'upgrade',
  'audit', 'settings', 'policy', 'notify', 'storage', 'accounts', 'threat-view',
  'ai-analyze',
])
const pendingThreatRestoreId = ref(null)

function saveNavState() {
  try {
    localStorage.setItem(NAV_STORE_KEY, JSON.stringify({
      section: section.value,
      page: page.value,
      eventListReturnPage: eventListReturnPage.value,
      threatEventId: page.value === 'threat-view' && activeEvent.value?.id ? activeEvent.value.id : null,
      rulesSection: rulesSection.value,
    }))
  } catch { /* ignore */ }
}

function restoreNavState() {
  try {
    const raw = JSON.parse(localStorage.getItem(NAV_STORE_KEY) || 'null')
    if (!raw?.page || !NAV_PAGES.has(raw.page)) return
    section.value = raw.section || 'overview'
    eventListReturnPage.value = raw.eventListReturnPage || 'events'
    if (raw.rulesSection) rulesSection.value = raw.rulesSection
    if (raw.page === 'threat-view' && raw.threatEventId) {
      pendingThreatRestoreId.value = Number(raw.threatEventId) || raw.threatEventId
      page.value = raw.eventListReturnPage === 'malware' ? 'malware' : 'events'
    } else {
      page.value = raw.page
    }
  } catch { /* ignore */ }
}
const menuMap = {
  overview: [
    {
      title: '态势',
      items: [
        { id: 'overview', label: '总览看板' },
        { id: 'events', label: '最近威胁' },
        { id: 'attck', label: 'ATT&CK 看板' },
      ],
    },
    {
      title: '调查',
      items: [
        { id: 'investigate', label: '日志调查' },
        { id: 'timeline', label: '主机时间线' },
        { id: 'hunt', label: '调查狩猎' },
        { id: 'dns', label: 'DNS 狩猎' },
        { id: 'ioc', label: '威胁情报 IOC' },
      ],
    },
    {
      title: '终端',
      items: [
        { id: 'hosts', label: '终端列表' },
      ],
    },
  ],
  detect: [
    {
      title: '检测响应',
      items: [{ id: 'events', label: '威胁事件' }],
    },
    {
      title: '威胁概览',
      items: [{ id: 'overview', label: '终端安全概览' }],
    },
    {
      title: '入侵防护',
      items: [{ id: 'malware', label: '恶意文件' }],
    },
    {
      title: '调查狩猎',
      items: [
        { id: 'behaviors', label: '检出行为' },
        { id: 'investigate', label: '日志调查' },
        { id: 'hunt', label: '威胁狩猎' },
        { id: 'timeline', label: '主机时间线' },
        { id: 'dns', label: 'DNS 狩猎' },
        { id: 'ioc', label: '威胁情报 IOC' },
      ],
    },
    {
      title: '策略配置',
      items: [{ id: 'whitelist', label: '信任名单' }],
    },
  ],
  rules: [{
    title: '规则管理',
    items: [
      { id: 'rules', label: 'Agent 规则' },
      { id: 'seq', label: '行为序列' },
    ],
  }],
  ai: [{
    title: 'AI 分析',
    items: [
      { id: 'ai-analyze', label: '一键研判' },
    ],
  }],
  asset: [{
    title: '调查资产',
    items: [
      { id: 'hosts', label: '终端列表' },
      { id: 'groups', label: '终端分组' },
    ],
  }],
  deploy: [{ title: '部署运营', items: [{ id: 'deploy', label: '安装包下载' }, { id: 'upgrade', label: '灰度升级' }, { id: 'audit', label: '处置审计' }] }],
  config: [{
    title: '平台配置',
    items: [
      { id: 'settings', label: '接入与地址' },
      { id: 'policy', label: 'EDR 策略' },
      { id: 'notify', label: '通知渠道' },
      { id: 'storage', label: '存储与保留' },
      { id: 'accounts', label: '账号管理', adminOnly: true },
    ],
  }],
}
const sectionTitle = computed(() => ({
  overview: '数据概览', detect: '检测响应', rules: '规则管理', asset: '终端资产', deploy: '部署运营', config: '平台配置',
}[section.value] || ''))
const menuGroups = computed(() => (menuMap[section.value] || []).map((g) => ({
  ...g,
  items: g.items.filter((m) => !m.adminOnly || isAdmin.value),
})))

const agents = ref([])
const selected = ref(null)
const q = ref('')
const loading = ref(false)
const error = ref('')
const okMsg = ref('')

/** AI 分析页 */
const aiBusy = ref(false)
const aiHostsLoading = ref(false)
const aiOnlyOnline = ref(true)
const aiHosts = ref([])
const aiSkills = ref([])
const aiSkillsMeta = ref({ total_indexed: 0, edr_relevant: 0, returned: 0 })
const aiStatusInfo = ref({})
let aiHostsTimer = null
let aiHostsInflight = null
const aiSelectedId = ref('')
const aiResult = ref(null)
const aiErrorText = ref('')
const aiRefining = ref(false)
const aiDispBusy = ref(false)
const aiThinkIdx = ref(0)
const aiEntityIdx = ref(0)
const aiThreatIdx = ref(0)
const aiLogIdx = ref(0)
const aiLogCat = ref('')
const aiChainNodeId = ref('')
const aiTab = ref('overview')
const aiThinkStep = computed(() => {
  const steps = aiResult.value?.result?.thinking_chain || []
  if (!steps.length) return null
  const i = Math.min(Math.max(0, aiThinkIdx.value), steps.length - 1)
  return steps[i]
})
const aiEntityCard = computed(() => {
  const list = aiResult.value?.result?.entities || []
  if (!list.length) return null
  const i = Math.min(Math.max(0, aiEntityIdx.value), list.length - 1)
  return list[i]
})
const aiEntityStats = computed(() => {
  const list = aiResult.value?.result?.entities || []
  let malicious = 0
  let suspicious = 0
  for (const e of list) {
    if (e?.risk === 'malicious') malicious += 1
    else if (e?.risk === 'suspicious') suspicious += 1
  }
  return { malicious, suspicious, total: list.length }
})
const aiThreatCard = computed(() => {
  const list = aiResult.value?.result?.threat_events || []
  if (!list.length) return null
  const i = Math.min(Math.max(0, aiThreatIdx.value), list.length - 1)
  return list[i]
})
const aiForensicsLogs = computed(() => {
  const r = aiResult.value?.result || {}
  const list = r.forensics_logs || r.security_logs || []
  return Array.isArray(list) ? list : []
})
const aiLogCategoryMap = computed(() => {
  const fromPack = aiResult.value?.pack_stats?.log_categories || aiResult.value?.result?.log_categories || {}
  if (fromPack && Object.keys(fromPack).length) return fromPack
  const map = {}
  for (const l of aiForensicsLogs.value) {
    const k = l?.category || 'other'
    map[k] = (map[k] || 0) + 1
  }
  return map
})
const aiFilteredForensicsLogs = computed(() => {
  const cat = aiLogCat.value
  const list = aiForensicsLogs.value
  if (!cat) return list
  return list.filter((l) => (l?.category || 'other') === cat)
})
const aiLogCard = computed(() => {
  const list = aiFilteredForensicsLogs.value
  if (!list.length) return null
  const i = Math.min(Math.max(0, aiLogIdx.value), list.length - 1)
  return list[i]
})
const aiChainNode = computed(() => {
  const nodes = aiResult.value?.result?.attack_graph?.nodes || []
  if (!nodes.length) return null
  const id = aiChainNodeId.value
  const hit = nodes.find((n) => n.id === id)
  return hit || nodes[Math.min(1, nodes.length - 1)] || nodes[0]
})
const aiMatchedSkillIds = computed(() => {
  const ids = new Set()
  for (const s of aiResult.value?.skills_used || []) {
    if (s?.id) ids.add(s.id)
  }
  return ids
})
const aiOnlineHosts = computed(() => (aiHosts.value || []).filter((h) => h.online))
const aiVisibleHosts = computed(() => {
  const list = aiHosts.value || []
  return aiOnlyOnline.value ? list.filter((h) => h.online) : list
})
const aiSelectedHost = computed(() => (aiHosts.value || []).find((h) => h.agent_id === aiSelectedId.value) || null)
const aiMarkdownHtml = computed(() => {
  const md = aiResult.value?.result?.markdown || aiResult.value?.result?.summary || ''
  if (String(md || '').trim()) return renderAiMarkdown(md)
  const highlights = aiResult.value?.result?.highlights || []
  if (highlights.length) {
    return renderAiMarkdown(
      `## 风险结论\n${aiResult.value?.result?.risk_level || '待复核'}\n\n## 关键证据\n`
      + highlights.map((h) => `- ${h}`).join('\n'),
    )
  }
  return renderAiMarkdown('暂无正文。请确认 Agent 已上报快照/威胁/日志后重试。')
})

let errorToastTimer = null
function clearErrorToast() {
  error.value = ''
  if (errorToastTimer) {
    clearTimeout(errorToastTimer)
    errorToastTimer = null
  }
}
watch(error, (msg) => {
  if (errorToastTimer) {
    clearTimeout(errorToastTimer)
    errorToastTimer = null
  }
  if (!msg) return
  errorToastTimer = setTimeout(() => {
    error.value = ''
    errorToastTimer = null
  }, 5000)
})
const module = ref('process')
const modules = ref(Object.keys(LABELS))
const hostTabGroup = ref('runtime')
const hostRemoteBusy = ref(false)
const hostRemoteCommands = ref([])
let hostRemotePollTimer = null
const hostRemoteForm = ref({ pid: '', path: '', scanPid: '' })
const hostRemoteSubTab = ref('ops')
const hostRemoteFsPath = ref('C:\\')
const hostRemoteFsEntries = ref([])
const hostRemoteFsDrives = ref([])
const hostRemoteFsRoots = ref([])
const hostRemoteFsHint = ref('')
const hostRemoteFsTruncated = ref(false)
const hostRemoteFsPreview = ref('')
const hostRemoteFsTree = computed(() => {
  const out = []
  const walk = (nodes, depth) => {
    for (const n of nodes || []) {
      out.push({ node: n, depth })
      if (n.expanded && n.children?.length) walk(n.children, depth + 1)
    }
  }
  walk(hostRemoteFsRoots.value, 0)
  return out
})
const hostRemoteFsDirCount = computed(() => hostRemoteFsEntries.value.filter((e) => e.dir).length)
const hostRemoteFsFileCount = computed(() => hostRemoteFsEntries.value.filter((e) => !e.dir).length)
const hostRemoteReg = ref({ hive: 'HKLM', key: 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', value: '' })
const hostRemoteRegResult = ref(null)
const hostRemoteRegBreadcrumb = computed(() => {
  const h = hostRemoteReg.value.hive || 'HKLM'
  const k = String(hostRemoteReg.value.key || '').trim()
  return k ? `${h}\\${k}` : h
})
const hostRemoteRegSubkeys = computed(() => hostRemoteRegResult.value?.subkeys || [])
const hostRemoteRegValues = computed(() => hostRemoteRegResult.value?.values || [])
const hostRemoteRegSingleValue = computed(() => {
  const r = hostRemoteRegResult.value
  if (!r || r.values) return null
  if (r.value_name == null && r.data == null && !r.data_hex) return null
  return { name: r.value_name || '(默认)', type: r.type, data: r.data || r.data_hex }
})
const hostRemoteCmdLine = ref('')
const hostRemoteCmdOut = ref('')
const hostRemoteCmdLog = ref([])
const hostLiveQueryTable = ref('processes')
const hostLiveQueryLimit = ref(200)
const hostLiveQueryRows = ref([])
const hostLiveQueryMeta = ref(null)
const liveQueryAuditItems = ref([])

async function loadLiveQueryAudit() {
  const aid = selected.value?.agent_id
  if (!aid) {
    liveQueryAuditItems.value = []
    return
  }
  try {
    const r = await listAgentAudit(200)
    liveQueryAuditItems.value = (r?.items || []).filter((a) =>
      a.agent_id === aid && String(a.action || '').includes('live_query'),
    ).slice(0, 40)
  } catch {
    liveQueryAuditItems.value = []
  }
}
const hostLiveQueryTableOptions = computed(() => {
  const fromAgent = selected.value?.health?.sensors?.live_query_tables
  if (Array.isArray(fromAgent) && fromAgent.length) {
    return fromAgent.map((t) => ({
      name: t.name || t,
      osquery_analog: t.osquery_analog || '',
    }))
  }
  return LIVE_QUERY_TABLES_DEFAULT
})
const hostLiveQueryCols = computed(() => {
  const keys = new Set()
  for (const row of hostLiveQueryRows.value.slice(0, 50)) {
    if (row && typeof row === 'object') Object.keys(row).forEach((k) => keys.add(k))
  }
  return [...keys].slice(0, 24)
})
const hostRemoteShellId = ref('')
const hostRemoteShellLines = ref([])
const hostRemoteShellInput = ref('')
const hostRemoteShellPhase = ref('idle') // idle | connecting | live | error
const hostRemoteShellViewRef = ref(null)
const hostRemoteShellInputRef = ref(null)
let hostRemoteShellPollTimer = null
let hostRemoteShellPollBusy = false

const hostRemoteShellStatusLabel = computed(() => {
  const m = {
    idle: '未连接 — 请先点「连接 Shell」',
    connecting: '正在连接终端…',
    live: '会话进行中',
    error: '连接失败',
  }
  return m[hostRemoteShellPhase.value] || m.idle
})
const hostRemoteShellHint = ref('')
const hostRemoteShellHintKind = ref('info')
const hostRemoteShellConnectDisabled = computed(() => {
  if (!selected.value?.online) return true
  if (hostRemoteShellPhase.value === 'connecting') return true
  if (hostRemoteShellPhase.value === 'live' && hostRemoteShellId.value) return true
  if (!isAdmin.value) return true
  return false
})
const hostGroupMods = computed(() => {
  const g = HOST_TAB_GROUPS.find((x) => x.id === hostTabGroup.value)
  return g?.mods || HOST_TAB_GROUPS[0].mods
})
const snap = ref(null)
const snapLoading = ref(false)
const snapError = ref('')
const snapRow = ref(null)
const snapQ = ref('')
const snapView = ref('hide_noise') // all | risk | hide_noise
const dlBusy = ref(false)
const dlProgress = ref('')
const dlError = ref('')
const release = ref(null)
const releaseBusy = ref(false)
const RELEASE_LABELS = {
  latest: '最新构建', stale: '源码已更新，EXE 过期', mismatch: 'EXE 与清单不一致',
  unverified: '无构建清单，无法验证', missing: '缺少 EXE',
}
const releaseLabel = computed(() => RELEASE_LABELS[release.value?.status] || release.value?.status || '—')
let releaseTimer = null
async function loadRelease() {
  try {
    release.value = await getAgentRelease()
    if (release.value?.building && !releaseTimer) {
      releaseTimer = setInterval(async () => {
        await loadRelease()
        if (!release.value?.building) { clearInterval(releaseTimer); releaseTimer = null }
      }, 2500)
    }
  } catch { /* 非管理员或未启动：忽略 */ }
}
async function doBuildRelease() {
  releaseBusy.value = true
  dlError.value = ''
  try {
    await buildAgentRelease()
    okMsg.value = '已开始在服务器构建 Agent'
    setTimeout(() => { okMsg.value = '' }, 2500)
    await loadRelease()
    // building 标志在后台线程里置位，稍等再查一次以启动轮询
    setTimeout(loadRelease, 1200)
  } catch (e) {
    dlError.value = e?.message || String(e)
  } finally {
    releaseBusy.value = false
  }
}
onUnmounted(() => { if (releaseTimer) clearInterval(releaseTimer) })

// ---- 终端凭据 / 健康 ----
const credSummary = ref(null)
const credBusy = ref(false)
async function loadCredentials() {
  try { credSummary.value = await getAgentCredentials() } catch { /* 非管理员：忽略 */ }
}
async function toggleSharedKey() {
  if (!credSummary.value) return
  const next = !credSummary.value.allow_shared_key
  if (!next && !window.confirm('关闭后，已持有专属凭据的终端不受影响；但仍在用共享密钥的老终端将无法上报，确认关闭？')) return
  credBusy.value = true
  try { credSummary.value = await setSharedKeyPolicy(next) } catch (e) { error.value = e?.message || String(e) } finally { credBusy.value = false }
}
async function toggleRevoke(a) {
  if (!a) return
  const revoke = !a.revoked
  if (!window.confirm(revoke ? `吊销 ${a.hostname || a.agent_id} 的凭据？该终端将无法再上报，直到恢复或重新注册。` : '恢复该终端的凭据？')) return
  try {
    await revokeAgent(a.agent_id, revoke)
    await Promise.all([softRefresh(), loadCredentials()])
  } catch (e) { error.value = e?.message || String(e) }
}
function healthChips(a) {
  const h = a?.health || {}
  if (!h || !Object.keys(h).length) return []
  const o = h.outbox || {}
  const chips = []
  if (h.cpu_pct != null) chips.push({ k: 'CPU', v: `${Number(h.cpu_pct).toFixed(1)}%`, warn: h.cpu_pct > 5 })
  if (h.rss_mb != null) chips.push({ k: '内存', v: `${Number(h.rss_mb).toFixed(0)} MB`, warn: h.rss_mb > 250 })
  if (o.depth != null) chips.push({ k: '待发队列', v: `${o.depth}`, warn: o.depth > 5000 })
  if (o.dropped) chips.push({ k: '已丢弃', v: `${o.dropped}`, warn: true })
  if (o.rejected) chips.push({ k: '被拒', v: `${o.rejected}`, warn: true })
  if (h.protocol) chips.push({ k: '协议', v: `v${h.protocol}`, warn: false })
  if (h.auth) chips.push({ k: '鉴权', v: h.auth === 'agent_secret' ? '专属凭据' : '共享密钥', warn: h.auth !== 'agent_secret' })
  if (a?.clock_skew_sec != null && Math.abs(a.clock_skew_sec) > 60) chips.push({ k: '时钟偏差', v: `${Math.round(a.clock_skew_sec)}s`, warn: true })
  const pol = h.policy
  if (pol && typeof pol === 'object') {
    const st = POLICY_STATUS_LABELS[pol.status] || pol.status
    chips.push({ k: '策略', v: `rev ${pol.applied_rev || '—'} · ${st}`, warn: pol.status === 'rejected' || pol.status === 'rolled_back', title: pol.error || '' })
  }
  const cs = h.sensors?.capture_status || h.capture_status
  if (cs && typeof cs === 'object') {
    if (cs.entities_rev != null) chips.push({ k: '实体 rev', v: String(cs.entities_rev), warn: false })
  }
  return chips
}

function captureStatusOf(agent) {
  const h = agent?.health || {}
  return h.sensors?.capture_status || h.capture_status || {}
}

function hostSensorsPanel(agent) {
  const s = agent?.health?.sensors || {}
  const ch = s.capture_health || {}
  const pipe = s.sensor_pipeline || {}
  const tele = s.telemetry || {}
  const disks = s.host_metrics?.disks
  let diskLine = ''
  if (Array.isArray(disks) && disks.length) {
    const worst = disks.reduce((a, b) => ((a?.used_pct || 0) > (b?.used_pct || 0) ? a : b))
    if (worst?.mount) diskLine = `${worst.mount}${worst.used_pct}%`
  }
  const outbox = agent?.health?.outbox || {}
  const byKind = outbox.by_kind || s.outbox?.by_kind || null
  let byKindLine = ''
  if (byKind && typeof byKind === 'object') {
    byKindLine = Object.entries(byKind)
      .sort((a, b) => (b[1] || 0) - (a[1] || 0))
      .slice(0, 6)
      .map(([k, v]) => `${k}:${v}`)
      .join(' ')
  }
  const net = s.host_metrics?.net_io || {}
  let netLine = ''
  if (net.nic_in_bytes != null || net.nic_out_bytes != null) {
    const fmt = (n) => {
      const x = Number(n) || 0
      if (x > 1e9) return `${(x / 1e9).toFixed(1)}G`
      if (x > 1e6) return `${(x / 1e6).toFixed(1)}M`
      if (x > 1e3) return `${(x / 1e3).toFixed(0)}K`
      return String(x)
    }
    netLine = `NIC ↓${fmt(net.nic_in_bytes)} ↑${fmt(net.nic_out_bytes)}`
  } else if (net.tcp_curr_estab != null) {
    netLine = `tcp estab ${net.tcp_curr_estab}`
  }
  const cs = captureStatusOf(agent)
  const statusChips = []
  if (cs?.etw_session_ok) statusChips.push({ label: 'ETW 正常', ok: true })
  else if (cs && Object.keys(cs).length) statusChips.push({ label: 'ETW 回退 Winlog', warn: true })
  if (cs && Object.keys(cs).length) {
    statusChips.push(cs.audit_4688_enabled
      ? { label: '4688 已开', ok: true }
      : { label: '4688 未开', warn: true, title: '进程创建审计未开，命令行补全可能不足' })
    statusChips.push(cs.sysmon_present
      ? { label: 'Sysmon', ok: true }
      : { label: '无 Sysmon', title: '可选增强' })
  }
  if (s.elastic_parity?.defend_kernel_tier === false) {
    statusChips.push({ label: '非 Defend 内核档', title: '对齐 Elastic Agent 编排，非 Defend 内核传感器' })
  }
  let channelChips = []
  const manifest = s.winevent_manifest
  if (Array.isArray(manifest) && manifest.length) channelChips = manifest.slice(0, 16)
  else if (typeof s.winevent_channels === 'number' && s.winevent_channels > 0) {
    channelChips = [`${s.winevent_channels} 通道`]
  }
  return {
    score: ch.score ?? null,
    level: ch.level || 'good',
    advise: ch.advise || [],
    pipeline: [pipe.primary, pipe.secondary].filter(Boolean).join('+') || s.etw || '—',
    cmdFill: tele.proc_cmd_fill_pct,
    disks: diskLine,
    byKind,
    byKindLine,
    netIo: net,
    netLine,
    parity: s.elastic_parity || null,
    statusChips,
    channelChips,
  }
}

function captureCaptureHint(agent) {
  const cs = captureStatusOf(agent)
  if (!cs || !Object.keys(cs).length) return ''
  const parts = []
  const pipe = agent?.health?.sensors?.sensor_pipeline || agent?.health?.fleet?.sensor_pipeline
  if (pipe?.primary) parts.push(`主:${pipe.primary}`)
  if (pipe?.secondary) parts.push(`辅:${pipe.secondary}`)
  const tele = agent?.health?.sensors?.telemetry || agent?.health?.fleet?.telemetry
  if (tele?.proc_cmd_fill_pct != null) parts.push(`cmd填充 ${tele.proc_cmd_fill_pct}%`)
  if (cs.etw_session_ok) parts.push('ETW 正常')
  else parts.push('ETW 未就绪，Winlog 补偿')
  parts.push(cs.audit_4688_enabled ? '4688 审计已开' : '4688 未开')
  parts.push(cs.sysmon_present ? 'Sysmon 已装' : '未检测到 Sysmon')
  const ch = agent?.health?.sensors?.winevent_channels
  if (ch) parts.push(`Winlog通道 ${ch}`)
  const manifest = agent?.health?.sensors?.winevent_manifest
  if (Array.isArray(manifest) && manifest.length) parts.push(manifest.join('+'))
  const disks = agent?.health?.sensors?.host_metrics?.disks
  if (Array.isArray(disks) && disks.length) {
    const worst = disks.reduce((a, b) => ((a?.used_pct || 0) > (b?.used_pct || 0) ? a : b))
    if (worst?.mount) parts.push(`盘 ${worst.mount} ${worst.used_pct}%`)
  }
  const ep = agent?.health?.sensors?.elastic_parity
  if (ep?.defend_kernel_tier === false) parts.push('非Defend内核档')
  return parts.join(' · ')
}

function componentHealthChips(agent) {
  const raw = agent?.health?.sensors?.components || agent?.health?.components || []
  if (!Array.isArray(raw)) return []
  return raw.map((c) => ({
    k: String(c.name || c.k || '?'),
    state: String(c.state || 'OK'),
    message: String(c.message || ''),
  }))
}
function componentWarnChips(agent) {
  return componentHealthChips(agent).filter((c) => c.state !== 'OK')
}
function hostQuickStats(agent) {
  return healthChips(agent).filter((c) => ['CPU', '内存', '待发队列', '已丢弃', '被拒', '时钟偏差'].includes(c.k))
}
const hostHdrMore = ref(false)
const hostHealthOpen = ref(false)
const events = ref([])
const allEvents = ref([])
const eventAgentId = ref('')
const focusKey = ref('')
const eventQName = ref('')
const eventIocQ = ref('')
const eventGroupId = ref('')
const eventTypeFilter = ref('')
/** 点「查询」后生效的筛选快照 */
const eventFiltersOn = ref({ name: '', ioc: '', group: '', type: '', sev: '' })
const openEventCount = ref(0)
const liveOk = ref(false)
const lastSyncAt = ref(0)
const nowTick = ref(Date.now())
// 默认按首次发现，避免 hit_count/updated_at 上涨时整表跳动
const eventSort = ref({ key: 'created_at', dir: 'desc' })
const eventSevFilter = ref('')
const behaviorCat = ref('')
const behaviorSev = ref('')
const bhNature = ref('')
const bhGroup = ref('')
const bhOs = ref('')
const bhQ = ref('')
const bhTactic = ref('')
const bhAgentId = ref('')
const bhPage = ref(1)
const bhPageSize = ref(20)
const selectedEventIds = ref([])
const respBusy = ref(false)
const diagBusy = ref(false)
const respCommands = ref([])
const respToast = ref(null)
let respToastTimer = null
let respToastCmdKey = ''
let respPollTimer = null
const timelineItems = ref([])
const timelineKinds = ref({})
const timelineTotal = ref(0)
const tlAgentId = ref('')
const tlQ = ref('')
const tlTypeFilter = ref('')
const tlOpenId = ref(null)
const huntQ = ref('')
const huntHits = ref([])
const huntBusy = ref(false)
const huntDone = ref(false)
const invQ = ref('')
const invRange = ref('1h')
const invBusy = ref(false)
const invItems = ref([])
const invCounts = ref({ all: 0, threat: 0, risk: 0, minor: 0, surface: 0 })
const invHist = ref([])
const invFacets = ref({ etype: [], hostname: [] })
const invFilters = ref({ nature: '', etype: '', hostname: '', path: '', hash_q: '', entity: '', tactic: '', os: '' })
const invNatureTab = ref('')
const invMoreFilters = ref(false)
/** 默认开启：压掉 info/low 普通 process_create，否则列表易被进程创建占满 */
const invHideProcNoise = ref(true)
const invDetail = ref(null)
const invDetailId = ref(null)
const invDetailTab = ref('info')
const invShowSaved = ref(false)
const invShowHist = ref(false)
const invSaved = ref([])
const invHistory = ref([])
const policyForm = ref({
  heartbeat_sec: 5,
  response_enabled: true,
  timeline_process: true,
  timeline_file: true,
  timeline_network: true,
  timeline_retain_days: 14,
  events_retain_days: 90,
  mysql_dual_write: true,
  self_protect: false,
  fim_enabled: true,
  fim_paths_text: '',
  log_tail_paths_text: '',
  winevent_channel_mode: 'all',
  winevent_channels_text: '',
  intervals_sec: { process: 5, network: 5, file: 12 },
  remote_ops_enabled: true,
  remote_ops_read_only: false,
  remote_ops_run_cmd: true,
  remote_ops_shell: true,
})
const iocItems = ref([])
const iocText = ref('')
const iocType = ref('hash')
const iocLib = ref(null)
const iocLibLocal = ref(0)
const attckCols = ref([])
const attckTop = ref([])
const attckHeat = ref([])
const attckHosts = ref([])
const attckTotal = ref(0)
const attckCovered = ref(0)
const attckAgent = ref('')
const attckDays = ref(7)
const attckItems = ref([])
const attckHigh = ref(0)
const attckOpen = ref(0)
const attckUnmapped = ref(0)
const attckSel = ref({ tactic: '', tech: '' })
const attckSelTacticName = computed(() => {
  const t = attckSel.value.tactic
  return t ? (attckHeat.value.find((h) => h.tactic === t)?.name || '') : ''
})
const attckTechList = computed(() => {
  const t = attckSel.value.tactic
  if (!t) return attckTop.value
  const row = attckHeat.value.find((h) => h.tactic === t)
  return (row?.techniques || []).map((x) => ({ ...x, tactic: t, tactic_name: row.name }))
})
const attckFiltered = computed(() => {
  const { tactic, tech } = attckSel.value
  return attckItems.value.filter((it) => (!tactic || it.tactic === tactic) && (!tech || it.technique === tech))
})
function cleanSummary(s) {
  return String(s || '').replace(/\(实时\)/g, '').replace(/\s{2,}/g, ' ').trim()
}
const notifyForm = ref({
  enabled: false, min_severity: 'high', webhook_url: '', feishu_webhook: '',
  dingtalk_webhook: '', dingtalk_secret: '', timeout_sec: 8,
})
const notifyTestResult = ref(null)
const storeInfo = ref(null)
const storeQ = ref('')
const storeHits = ref([])
const storyNodes = ref([])
const relatedPayload = ref(null)
const storyTech = ref([])
const upPackages = ref([])
const upFile = ref(null)
const upVer = ref('')
const upNote = ref('')
const upPkgId = ref('')
const upAgentIds = ref([])
const upCommands = ref([])
const upgradeDriftRows = computed(() => {
  return Object.values(fleetDriftByAgent.value || {}).filter((x) => x?.drift && x?.online)
})

const upgradeFleetRows = computed(() => {
  const byAgent = {}
  for (const c of upCommands.value || []) {
    const aid = c.agent_id
    if (!aid) continue
    if (c.action === 'upgrade' || c.action === 'rollback_upgrade') {
      if (!byAgent[aid] || String(c.created_at || '') > String(byAgent[aid].created_at || '')) {
        byAgent[aid] = c
      }
    }
  }
  return (agents.value || []).map((a) => {
    const h = a.health || {}
    const fleet = h.fleet || h.fleet_report || {}
    const ud = h.upgrade_details
    let udText = ''
    if (ud && typeof ud === 'object') {
      const sn = ud.state_name || UPGRADE_STATE_LABELS[ud.state] || ud.state
      udText = [sn, ud.target_version ? `v${ud.target_version}` : ''].filter(Boolean).join(' · ')
    }
    const cmd = byAgent[a.agent_id]
    const lastCmd = cmd
      ? `${cmd.action} · ${cmd.status}${cmd.result_json ? '' : ''}`
      : ''
    const sensors = h.sensors || {}
    const pipe = sensors.sensor_pipeline || fleet.sensor_pipeline || {}
    const tele = sensors.telemetry || fleet.telemetry || {}
    const sp = fleet.sync_parts || {}
    const syncOk = sp.all_ok
    const pipeLine = [pipe.primary, pipe.secondary].filter(Boolean).join('+') || '—'
    const teleBits = []
    if (tele.proc_cmd_fill_pct != null) teleBits.push(`cmd ${tele.proc_cmd_fill_pct}%`)
    if (tele.events_etw != null) teleBits.push(`etw ${tele.events_etw}`)
    if (tele.events_winevent != null) teleBits.push(`wevt ${tele.events_winevent}`)
    const telemetryHint = captureCaptureHint(a)
    return {
      agent_id: a.agent_id,
      hostname: a.hostname,
      online: a.online,
      version: a.version,
      policy_applied: !!(fleet.policy_applied ?? h.policy_applied),
      local_sync_rev: fleet.local_sync_rev ?? '—',
      local_policy_rev: fleet.local_policy_rev ?? '—',
      upgrade_details: udText,
      telemetry_line: `${pipeLine}${syncOk === false ? ' · sync✗' : syncOk === true ? ' · sync✓' : ''}${teleBits.length ? ' · ' + teleBits.join(' ') : ''}`,
      telemetry_hint: telemetryHint,
      last_upgrade_cmd: lastCmd,
    }
  })
})
const upBusy = ref(false)
const upPushBusy = ref(false)
const upError = ref('')
const upOk = ref('')
const diagHistoryItems = ref([])

async function loadDiagHistory() {
  try {
    const r = await listAgentDiagnostics('', 80)
    diagHistoryItems.value = r?.items || r?.diagnostics || []
  } catch (e) {
    diagHistoryItems.value = []
  }
}

async function cancelHostUpgrade(row) {
  if (!row?.agent_id) return
  try {
    await createAgentCommand(row.agent_id, 'cancel_upgrade', {})
    upOk.value = `已下发取消升级：${row.hostname || short(row.agent_id)}`
  } catch (e) {
    upError.value = e?.message || String(e)
  }
}
const seqRules = ref([])
const groupItems = ref([])
const groupName = ref('')
const groupIds = ref('')
const auditItems = ref([])
const tagMap = ref({})
const hostTagEdit = ref('')
const policyRev = ref(0)
const whitelist = ref([])
const wlKind = ref('process')
const wlValue = ref('')
const wlNote = ref('')
const wlRule = ref('')
const allowDlg = ref(null)
const allowSubmitReady = computed(() => {
  const d = allowDlg.value
  if (!d || d.loading || d.busy) return false
  const picks = d.picks || []
  if (!picks.length) return false
  if (picks.length === 1) return String(d.value || '').trim().length > 0
  return picks.every((i) => String(d.items?.[i]?.value || '').trim().length > 0)
})
const allowDlgHasNonTitlePick = computed(() => {
  const d = allowDlg.value
  if (!d?.items?.length || !d.picks?.length) return false
  return d.picks.some((i) => d.items[i]?.kind && d.items[i].kind !== 'title')
})
const ALLOW_KIND_LABELS = {
  process: '进程名', path: '文件路径', hash: '文件哈希', signer: '签名者', cmdline: '命令行',
  registry: '注册表键', domain: '域名', ip: 'IP', title: '告警标题',
}
const WL_KIND_HINTS = {
  process: '如 evil.exe，匹配进程映像名',
  path: '支持通配，如 C:\\Users\\Public\\*\\*.exe',
  hash: 'SHA256 / MD5 完整或前缀',
  signer: '签名主题名或发布者',
  cmdline: '命令行子串或通配',
  registry: '注册表键路径（Hive\\…）',
  domain: 'DNS / IOC 域名',
  ip: '远端或本地 IP',
  title: '仅抑制标题匹配的告警',
}
function wlKindHint(k) {
  return WL_KIND_HINTS[k] || '按匹配值抑制同类告警'
}
let stopStream = null
let liveTickTimer = null
const agentServerUrl = ref('')
const saving = ref(false)
const activeEvent = ref(null)
const threatTab = ref('graph')
const threatTree = ref(null)
const threatTreeBusy = ref(false)
const tvTreeExpanded = ref({})
const tvShowDotted = ref(true)
const tvReadable = ref(true)
const tvZoom = ref(1)
const threatPanelNode = ref('hit')
const ruleStats = ref(null)
const agentRules = ref([])
const rulesFilter = ref('all') // all | sensor | custom | elastic
const rulesBulkBusy = ref(false)
const settingsRulesFilter = ref('all')
const filteredAgentRules = computed(() => {
  const all = agentRules.value || []
  if (rulesFilter.value === 'sensor') return all.filter((r) => r.builtin || r.source === 'sensor')
  if (rulesFilter.value === 'custom') return all.filter((r) => !(r.builtin || r.source === 'sensor'))
  if (rulesFilter.value === 'elastic') return all.filter((r) => isElasticRule(r))
  return all
})
const ruleStatsItems = computed(() => {
  const fromStats = ruleStats.value?.items
  if (Array.isArray(fromStats) && fromStats.length) return fromStats
  return agentRules.value || []
})
const filteredSettingsRules = computed(() => {
  const all = ruleStatsItems.value || []
  if (settingsRulesFilter.value === 'sensor') return all.filter((r) => r.builtin || r.source === 'sensor')
  if (settingsRulesFilter.value === 'custom') return all.filter((r) => !(r.builtin || r.source === 'sensor'))
  return all
})
const editingRule = ref(null)
const ruleCreating = ref(false)
const ruleSaving = ref(false)
const ruleFormError = ref('')
const rulesSection = ref('detect')
const wlListFilter = ref('all')
const wlSearch = ref('')
const whitelistEnabledCount = computed(() => (whitelist.value || []).filter((w) => w.enabled).length)
const filteredWhitelist = computed(() => {
  let rows = whitelist.value || []
  if (wlListFilter.value === 'enabled') rows = rows.filter((w) => w.enabled)
  if (wlListFilter.value === 'disabled') rows = rows.filter((w) => !w.enabled)
  const q = String(wlSearch.value || '').trim().toLowerCase()
  if (q) {
    rows = rows.filter((w) =>
      String(w.value || '').toLowerCase().includes(q)
      || String(w.note || '').toLowerCase().includes(q)
      || String(w.rule || '').toLowerCase().includes(q)
      || String(ALLOW_KIND_LABELS[w.kind] || w.kind || '').toLowerCase().includes(q))
  }
  return rows
})
const memoryYaraPack = ref(null)
const memoryYaraView = ref('strings')
const memoryYaraBusy = ref(false)
const memoryYaraErr = ref('')
const memoryYaraControlsBusy = ref(false)
const MEMORY_YARA_GROUP_KEYS = ['protections_yara', 'builtin_yara', 'valhalla_yara', 'string_rules']
const overviewStats = ref({})
const fleetDriftByAgent = ref({})
const UPGRADE_STATE_LABELS = {
  0: 'STARTING',
  1: 'CONFIGURING',
  2: 'HEALTHY',
  3: 'DEGRADED',
  4: 'FAILED',
  7: 'UPGRADING',
  8: 'ROLLBACK',
  DOWNLOADING: '下载中',
  VERIFYING: '校验中',
  REPLACING: '替换中',
  UPGRADING: '升级中',
  WATCHDOG: '看门狗',
  ROLLBACK: '回滚中',
}
const ovFleetCollapsed = ref(false)
const autoEnrichOnLoad = ref(localStorage.getItem('edr_auto_enrich_events') === '1')
const agentSyncManifest = ref(null)
const agentSyncBusy = ref(false)
const agentSyncBumpBusy = ref(false)
const agentIntegrations = ref(null)
const agentIntegrationsOpen = ref(false)
const agentIntegrationsBusy = ref(false)
const agentIntegrationsErr = ref('')
const AGENT_INTEGRATION_GROUPS = [
  {
    id: 'detect',
    title: '端上 · 检测引擎',
    hint: '影响 Agent 本机 CPU；EVM/AMSI/内存 YARA 对 PowerShell、LOLBin 样本最相关。',
    keys: ['evm', 'ptm', 'amsi', 'api_etw', 'memory_scan'],
  },
  {
    id: 'collect',
    title: '端上 · 采集与监控',
    hint: 'ETW 为主通道；WMI 进程订阅默认关闭，可按需打开。',
    keys: ['etw', 'winevent', 'wmi_process', 'fim', 'registry'],
  },
  {
    id: 'compliance',
    title: '端上 · 合规与基线',
    keys: ['sca', 'rootcheck'],
  },
]
const SERVER_DETECTION_UI_KEYS = ['evm_ingest', 'elastic_evm_ingest', 'lolbin_ingest']
const ruleForm = ref(emptyRuleForm())
let timer = null

function emptyRuleForm() {
  return {
    title: '',
    severity: 'high',
    modules: ['process'],
    fieldsText: 'path,command_line,name',
    patternsText: '',
    fileExts: [],
    fileExtsText: '',
    signedFilter: '',
    pathPrefixesText: '',
    match: 'substring',
    enabled: true,
    note: '',
    etype: '',
  }
}

function isElasticRule(r) {
  if (!r) return false
  if (r.source === 'elastic') return true
  const id = String(r.id || '')
  if (id.startsWith('elastic-')) return true
  if (r.elastic_rule_id) return true
  const note = String(r.note || '')
  return note.startsWith('Elastic:') || note.startsWith('Elastic EVM')
}

const isEditingSensor = computed(() => !!(
  editingRule.value && (editingRule.value.builtin || editingRule.value.source === 'sensor')
))

const isEditingElastic = computed(() => !!(
  editingRule.value && isElasticRule(editingRule.value) && !isEditingSensor.value
))

const isEditingEvmOnly = computed(() => !!(
  isEditingElastic.value && (editingRule.value?.rule_channel === 'evm' || /\.(evm|fim)$/i.test(String(editingRule.value?.id || '')))
))

const elasticOfficialDetail = ref(null)
const elasticOfficialBusy = ref(false)

function emptySeqForm() {
  return {
    title: '',
    severity: 'high',
    window_sec: 120,
    enabled: true,
    note: '',
    steps: [
      { etype_contains: 'process', summary_contains: '', name_regex: '' },
      { etype_contains: 'process', summary_contains: '', name_regex: '' },
    ],
  }
}

const editingSeq = ref(null)
const seqCreating = ref(false)
const seqSaving = ref(false)
const seqFormError = ref('')
const seqForm = ref(emptySeqForm())

const suggestedFields = computed(() => {
  if (isEditingSensor.value) {
    return [
      'summary', 'path', 'name', 'command_line', 'process_name',
      'user', 'signed', 'remote', 'query', 'script_block',
    ]
  }
  const set = new Set()
  for (const m of ruleForm.value.modules || []) {
    for (const f of FIELD_BY_MODULE[m] || []) set.add(f)
  }
  return [...set]
})
const fieldsSet = computed(() => new Set(
  String(ruleForm.value.fieldsText || '').split(/[,;\s]+/).map((x) => x.trim()).filter(Boolean),
))

const onlineCount = computed(() => agents.value.filter((a) => a.online).length)
/** 概览顶栏终端数以实时 agents 为准（overviewStats 仅定时刷新，避免新上线主机要手动 F5） */
const ovAgentTotal = computed(() => agents.value.length)

function sparklinePoints(buckets, w = 120, h = 32) {
  const arr = Array.isArray(buckets) ? buckets : []
  if (!arr.length) return ''
  const max = Math.max(...arr, 1)
  return arr
    .map((v, i) => {
      const x = (i / Math.max(arr.length - 1, 1)) * w
      const y = h - (Number(v) / max) * (h - 6) - 3
      return `${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')
}
const overviewSparkTl = computed(() => sparklinePoints(overviewStats.value?.timeline_24h?.buckets))
const overviewSparkDns = computed(() => sparklinePoints(overviewStats.value?.dns_24h?.buckets))
const overviewTopMalware = computed(() => overviewStats.value?.threats?.top_malware || [])

async function loadOverview() {
  try {
    overviewStats.value = await getEdrOverview(45)
  } catch {
    overviewStats.value = {}
  }
  try {
    const fd = await getFleetDrift(45)
    const map = {}
    for (const it of fd?.items || []) {
      if (it?.agent_id) map[it.agent_id] = it
    }
    fleetDriftByAgent.value = map
  } catch {
    fleetDriftByAgent.value = {}
  }
  loadAgentSyncManifest({ silent: true }).catch(() => {})
}

const ovOnlineCaptureHint = computed(() => {
  const online = agents.value.filter((a) => a.online)
  if (!online.length) return ''
  let etwBad = 0
  let no4688 = 0
  for (const a of online) {
    const cs = captureStatusOf(a)
    if (cs.etw_session_ok === false) etwBad++
    if (cs.audit_4688_enabled === false) no4688++
  }
  const parts = []
  if (etwBad) parts.push(`${etwBad} 台 ETW 未就绪`)
  if (no4688) parts.push(`${no4688} 台未开 4688 审计`)
  if (!parts.length) return '在线终端采集通道正常（ETW / 事件日志）'
  return parts.join(' · ') + '，命令行可能不全'
})

const ovDriftHint = computed(() => {
  const n = overviewStats.value?.agents?.component_drift ?? 0
  const p = overviewStats.value?.agents?.policy_drift ?? 0
  if (!n && !p) return ''
  const parts = []
  if (n) parts.push(`${n} 台在线终端组件 expected/actual 漂移`)
  if (p) parts.push(`${p} 台 PolicyApplied 未收敛`)
  return parts.join(' · ') + '（见灰度升级页或终端详情）'
})

function agentDriftRow(agentId) {
  return fleetDriftByAgent.value?.[agentId] || null
}

function agentDriftLine(agent) {
  const d = agentDriftRow(agent?.agent_id)
  if (!d?.drift) return ''
  const parts = []
  if (d.missing?.length) parts.push(`缺失: ${d.missing.join(',')}`)
  if (d.failed?.length) parts.push(`失败: ${d.failed.join(',')}`)
  if (d.degraded?.length) parts.push(`降级: ${d.degraded.join(',')}`)
  if (d.sync_drift) parts.push(`sync ${d.local_sync_rev}<${d.server_sync_rev}`)
  if (d.policy_drift) parts.push('PolicyApplied 未收敛')
  return `Fleet 漂移 · ${parts.join(' · ')}`
}

function parseCmdResult(cmd) {
  if (!cmd) return {}
  let r = cmd.result_json ?? cmd.result
  if (typeof r === 'string' && r.trim()) {
    try { r = JSON.parse(r) } catch { r = {} }
  }
  return r && typeof r === 'object' ? r : {}
}

function setAutoEnrichOnLoad(on) {
  autoEnrichOnLoad.value = !!on
  localStorage.setItem('edr_auto_enrich_events', on ? '1' : '0')
}

async function maybeAutoEnrichEvents() {
  if (!autoEnrichOnLoad.value || !isAdmin.value) return
  try {
    await enrichEventDetails(120)
    await loadEvents(false)
  } catch { /* ignore */ }
}

async function requestDiagnostics(a) {
  if (!a?.agent_id || diagBusy.value) return
  diagBusy.value = true
  error.value = ''
  try {
    const r = await createAgentCommand(a.agent_id, 'collect_diagnostics', {})
    const cmdId = r?.item?.id || r?.id
    if (!cmdId) {
      okMsg.value = '诊断任务已下发'
      return
    }
    okMsg.value = `诊断采集中… (#${cmdId.slice(0, 8)})`
    for (let i = 0; i < 45; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2500))
      const lr = await listAgentCommands(a.agent_id)
      const cmd = (lr?.items || []).find((x) => x.id === cmdId)
      if (!cmd) continue
      if (cmd.status === 'failed') {
        throw new Error('诊断采集失败')
      }
      if (cmd.status === 'done') {
        const meta = parseCmdResult(cmd)
        if (meta.stored || meta.download_command_id) {
          await downloadAgentDiagnostics(a.agent_id, cmdId)
          okMsg.value = `诊断包已下载 · ${meta.filename || 'zip'} (${fmtSize(meta.size)})`
        } else {
          okMsg.value = '诊断已完成，但服务端未收到 zip，请稍后重试'
        }
        return
      }
    }
    okMsg.value = `指令 #${cmdId.slice(0, 8)} 仍在执行，可稍后在终端页再次点击「诊断包」`
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    diagBusy.value = false
  }
}
const filteredAgents = computed(() => {
  const s = q.value.trim().toLowerCase()
  if (!s) return agents.value
  return agents.value.filter((a) => `${a.hostname || ''} ${a.ip || ''} ${a.agent_id || ''}`.toLowerCase().includes(s))
})
const recentThreats = computed(() => allEvents.value.slice(0, 8))
const ovStatus = computed(() => {
  const out = { open: 0, closed: 0, ignored: 0 }
  for (const e of allEvents.value) out[e.status in out ? e.status : 'open'] += 1
  return out
})
const ovSevDist = computed(() => {
  const defs = [['critical', '严重'], ['high', '高危'], ['medium', '中危'], ['low', '低危'], ['info', '信息']]
  const cnt = Object.fromEntries(defs.map(([k]) => [k, 0]))
  for (const e of allEvents.value) if (e.severity in cnt) cnt[e.severity] += 1
  const max = Math.max(1, ...Object.values(cnt))
  return defs.map(([key, label]) => ({ key, label, count: cnt[key], pct: Math.round((cnt[key] / max) * 100) }))
})
const ovTrend = computed(() => {
  const days = []
  const now = new Date()
  for (let i = 6; i >= 0; i -= 1) {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - i)
    const day = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`
    days.push({ day, label: `${d.getMonth() + 1}/${d.getDate()}`, count: 0, high: 0 })
  }
  const idx = Object.fromEntries(days.map((d, i) => [d.day, i]))
  let total = 0
  for (const e of allEvents.value) {
    const i = idx[String(e.created_at || '').slice(0, 10)]
    if (i == null) continue
    days[i].count += 1
    total += 1
    if (e.severity === 'high' || e.severity === 'critical') days[i].high += 1
  }
  const max = Math.max(1, ...days.map((d) => d.count))
  return { total, days: days.map((d) => ({ ...d, pct: Math.round((d.count / max) * 100), hpct: Math.round((d.high / max) * 100) })) }
})
const ovTopHosts = computed(() => {
  const m = new Map()
  for (const e of allEvents.value) {
    const r = m.get(e.agent_id) || { agent_id: e.agent_id, hostname: e.hostname || short(e.agent_id), count: 0, high: 0 }
    r.count += 1
    if (e.severity === 'high' || e.severity === 'critical') r.high += 1
    m.set(e.agent_id, r)
  }
  return [...m.values()].sort((a, b) => b.high - a.high || b.count - a.count).slice(0, 5)
})
const ovTactics = computed(() => {
  const cnt = {}
  for (const e of allEvents.value) {
    const t = guessAttck(e.title, e.module).tactic
    if (t) cnt[t] = (cnt[t] || 0) + 1
  }
  return Object.entries(TACTIC_CN).map(([key, label]) => ({ key, label, count: cnt[key] || 0 }))
})
function isThreatSev(s) {
  return s === 'critical' || s === 'high'
}
function agentGroupIdOf(agentId) {
  const hit = (groupItems.value || []).find((g) => (g.agent_ids || []).includes(agentId))
  return hit?.id || ''
}
function agentOsOf(agentId) {
  const a = agents.value.find((x) => x.agent_id === agentId)
  return a?.os_family || '—'
}
function eventUserHint(e) {
  try {
    const raw = parseEventEvidence(e)
    const flat = evidenceFlatOf(raw)
    const u = String(flat.user || flat.username || flat.account || '').trim()
    if (u) return u.includes('\\') ? u.split('\\').pop() : u
    const p = String(flat.path || flat.image || flat.command_line || e.detail || '')
    const m = p.match(/\\Users\\([^\\]+)\\/i)
    return m ? m[1] : '—'
  } catch {
    return '—'
  }
}
const bhOsOptions = computed(() => {
  const s = new Set()
  for (const a of agents.value) {
    if (a.os_family) s.add(a.os_family)
  }
  return [...s]
})
const behaviorEvents = computed(() => {
  let list = [...allEvents.value]
  if (behaviorCat.value) list = list.filter((e) => catOf(e) === behaviorCat.value)
  if (behaviorSev.value) list = list.filter((e) => e.severity === behaviorSev.value)
  if (bhNature.value === 'threat') list = list.filter((e) => isThreatSev(e.severity))
  if (bhNature.value === 'risk') list = list.filter((e) => !isThreatSev(e.severity))
  if (bhAgentId.value) list = list.filter((e) => e.agent_id === bhAgentId.value)
  if (bhGroup.value) list = list.filter((e) => agentGroupIdOf(e.agent_id) === bhGroup.value)
  if (bhOs.value) list = list.filter((e) => agentOsOf(e.agent_id) === bhOs.value)
  if (bhTactic.value) list = list.filter((e) => guessAttck(e.title, e.module).tactic === bhTactic.value)
  const q = bhQ.value.trim().toLowerCase()
  if (q) {
    list = list.filter((e) => `${e.title || ''} ${e.hostname || ''} ${e.detail || ''}`.toLowerCase().includes(q))
  }
  return list
})
const bhPageCount = computed(() => Math.max(1, Math.ceil(behaviorEvents.value.length / bhPageSize.value)))
const pagedBhEvents = computed(() => {
  const start = (bhPage.value - 1) * bhPageSize.value
  return behaviorEvents.value.slice(start, start + bhPageSize.value)
})
watch([behaviorEvents, bhPageSize], () => {
  if (bhPage.value > bhPageCount.value) bhPage.value = bhPageCount.value
})
const bhThreatN = computed(() => allEvents.value.filter((e) => isThreatSev(e.severity)).length)
const bhRiskN = computed(() => allEvents.value.filter((e) => !isThreatSev(e.severity)).length)
const bhTopThreats = computed(() => {
  const m = new Map()
  for (const e of allEvents.value) {
    const t = String(e.title || '未知').slice(0, 80)
    m.set(t, (m.get(t) || 0) + 1)
  }
  return [...m.entries()].map(([title, count]) => ({ title, count })).sort((a, b) => b.count - a.count).slice(0, 8)
})
const bhTopMax = computed(() => bhTopThreats.value[0]?.count || 1)
const bhTacticRing = computed(() => {
  const cnt = {}
  for (const e of allEvents.value) {
    const t = guessAttck(e.title, e.module).tactic
    if (t) cnt[t] = (cnt[t] || 0) + 1
  }
  return TACTIC_STAGE.map((s) => ({
    ...s,
    label: TACTIC_CN[s.key] || s.stageLabel,
    count: cnt[s.key] || 0,
  }))
})
const bhTacticHitN = computed(() => bhTacticRing.value.filter((t) => t.count > 0).length)
const bhWavePath = computed(() => {
  const n = 12
  const w = 720
  const pad = 36
  const pts = []
  for (let i = 0; i < n; i++) {
    const x = pad + (i * (w - pad * 2)) / (n - 1)
    const y = i % 2 === 0 ? 42 : 98
    pts.push([x, y])
  }
  let d = `M ${pts[0][0]} ${pts[0][1]}`
  for (let i = 1; i < pts.length; i++) {
    const [x0, y0] = pts[i - 1]
    const [x1, y1] = pts[i]
    const cx = (x0 + x1) / 2
    d += ` C ${cx} ${y0}, ${cx} ${y1}, ${x1} ${y1}`
  }
  return d
})
function bhWaveNodeStyle(i, t) {
  const n = 12
  const pct = n <= 1 ? 50 : (i / (n - 1)) * 100
  const top = i % 2 === 0 ? '28%' : '72%'
  const c = t?.color || '#e11d2e'
  return {
    left: `${pct}%`,
    top,
    background: t?.count ? `linear-gradient(145deg, ${c}, ${c}cc)` : undefined,
  }
}
function stageIconPath(icon) {
  return STAGE_ICON_PATH[icon] || STAGE_ICON_PATH.key
}
const bhHostList = computed(() => {
  const m = new Map()
  for (const e of behaviorEvents.value) {
    const r = m.get(e.agent_id) || {
      agent_id: e.agent_id,
      hostname: e.hostname || short(e.agent_id),
      count: 0,
      online: !!agents.value.find((a) => a.agent_id === e.agent_id)?.online,
    }
    r.count += 1
    m.set(e.agent_id, r)
  }
  return [...m.values()].sort((a, b) => b.count - a.count)
})
function bhBarPct(n, max) {
  const m = max != null ? max : Math.max(bhThreatN.value + bhRiskN.value, 1)
  return Math.max(4, Math.round((Number(n || 0) / m) * 100))
}
function resetBhFilters() {
  bhNature.value = ''
  bhGroup.value = ''
  bhOs.value = ''
  bhQ.value = ''
  bhTactic.value = ''
  bhAgentId.value = ''
  behaviorSev.value = ''
  behaviorCat.value = ''
  bhPage.value = 1
}
function behaviorKind(e) {
  const t = String(e?.title || '')
  if (/规则命中/.test(t)) return '规则'
  if (/IOC|情报/.test(t)) return 'IOC'
  if (/序列|链式/.test(t)) return '序列'
  if (/ETW|可疑目录|DLL|注册表|FIM|持久化|远程线程|内核/.test(t)) return '传感器'
  const m = String(e?.module || '')
  if (['timeline', 'etw', 'kernel', 'registry', 'image', 'inject', 'dns', 'account', 'audit', 'script'].includes(m)) return '传感器'
  return '告警'
}
const recentRiskTimeline = computed(() => {
  const sevOk = new Set(['critical', 'high', 'medium'])
  return (timelineItems.value || [])
    .filter((t) => sevOk.has(String(t.severity || '').toLowerCase()))
    .slice(0, 8)
})
function selectHostGroup(gid) {
  const g = HOST_TAB_GROUPS.find((x) => x.id === gid)
  if (!g) return
  hostTabGroup.value = gid
  if (gid === 'remote') {
    loadHostRemoteCommands()
    if (hostRemoteSubTab.value === 'files' && selected.value?.online) hostRemoteFsLoadVolumes()
    if (hostRemoteSubTab.value === 'livequery') loadLiveQueryAudit()
    if (hostRemoteShellPhase.value === 'connecting') {
      hostRemoteShellPhase.value = 'idle'
      hostRemoteShellHint.value = '上次连接未完成，请重新点击「连接 Shell」'
      hostRemoteShellHintKind.value = 'warn'
    }
    return
  }
  if (gid === 'inventory') snapView.value = 'all'
  const cur = module.value
  if (g.mods.length && !g.mods.includes(cur)) {
    loadSnap(g.mods[0])
  }
}
function syncHostTabGroup(mod) {
  if (hostTabGroup.value === 'remote') return
  const hit = HOST_TAB_GROUPS.find((g) => g.mods.includes(mod))
  if (hit) hostTabGroup.value = hit.id
}

function refreshHostDetail() {
  if (hostTabGroup.value === 'remote') {
    loadHostRemoteCommands()
    return
  }
  loadSnap(module.value)
}
const hostsWithAlert = computed(() => {
  const ids = new Set(allEvents.value.map((e) => e.agent_id))
  return agents.value.filter((a) => ids.has(a.agent_id)).length
})
const hostAlerts = computed(() => {
  if (!selected.value) return []
  return allEvents.value.filter((e) => e.agent_id === selected.value.agent_id && (e.status || 'open') === 'open').slice(0, 12)
})
const hostRiskItems = ref([])
const hostRiskLoading = ref(false)
const hostSensorLabel = computed(() => {
  const kinds = new Set((hostRiskItems.value || []).map((x) => x.channel).filter(Boolean))
  if (kinds.has('kernel')) return '内核通道'
  if (kinds.has('etw')) return 'ETW'
  if (kinds.has('wmi') || kinds.has('live')) return 'WMI 实时'
  return '快照 / 轮询'
})
function alertCount(agentId) {
  return allEvents.value.filter((e) => e.agent_id === agentId).length
}
function riskChannel(etype) {
  const e = String(etype || '')
  if (e.includes('kernel')) return 'kernel'
  if (e.includes('etw')) return 'etw'
  if (e.includes('live') || e.includes('wmi')) return 'wmi'
  return 'poll'
}
function isSuspiciousTl(t) {
  const sev = String(t.severity || 'info')
  if (['medium', 'high', 'critical'].includes(sev)) return true
  const et = String(t.etype || '')
  if (/remote_thread|protect_block|image_load|file_write|可疑|临时|Public|inject/i.test(`${et} ${t.summary || ''}`)) return true
  return false
}
async function loadHostRisk() {
  if (!selected.value?.agent_id) {
    hostRiskItems.value = []
    return
  }
  hostRiskLoading.value = true
  try {
    const aid = selected.value.agent_id
    const r = await listTimeline({ agentId: aid, limit: 120 })
    const tl = (r?.items || []).filter(isSuspiciousTl).slice(0, 20).map((t) => ({
      key: `tl-${t.id}`,
      kind: 'timeline',
      kindLabel: etypeLabel(t.etype),
      severity: t.severity || 'medium',
      title: t.summary || etypeLabel(t.etype),
      ts: t.ts || t.created_at,
      channel: riskChannel(t.etype),
      raw: t,
    }))
    const threats = hostAlerts.value.map((e) => ({
      key: `ev-${e.id}`,
      kind: 'threat',
      kindLabel: '威胁',
      severity: e.severity || 'high',
      title: e.title,
      ts: e.created_at,
      channel: '',
      raw: e,
    }))
    hostRiskItems.value = [...threats, ...tl]
      .sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')))
      .slice(0, 24)
  } catch {
    hostRiskItems.value = hostAlerts.value.map((e) => ({
      key: `ev-${e.id}`,
      kind: 'threat',
      kindLabel: '威胁',
      severity: e.severity || 'high',
      title: e.title,
      ts: e.created_at,
      channel: '',
      raw: e,
    }))
  } finally {
    hostRiskLoading.value = false
  }
}
function openHostRiskItem(it) {
  if (it.kind === 'threat' && it.raw?.id) {
    openEvent(it.raw)
    return
  }
  if (it.kind === 'timeline') {
    openTimelineFor(selected.value?.agent_id)
    tlOpenId.value = it.raw?.id || null
  }
}
function agentIp(agentId) {
  return agents.value.find((a) => a.agent_id === agentId)?.ip || '—'
}
function shortPath(p) {
  const s = String(p || '')
  if (s.length <= 48) return s || '—'
  return `…${s.slice(-46)}`
}
const ruleCountLabel = computed(() => {
  const n = ruleStats.value?.enabled ?? agentRules.value.filter((r) => r.enabled).length
  return n != null ? String(n) : '—'
})

const MODULE_CAT = {
  registry: 'persist', service: 'persist', task: 'persist', startup: 'persist',
  process: 'proc', inject: 'proc', image: 'proc', memory: 'proc', kernel: 'proc',
  file: 'file', network: 'net', dns: 'net', listen: 'net',
  account: 'account', audit: 'account', user: 'account',
  script: 'script', ioc: 'ioc', sequence: 'rule',
}
const ETYPE_CAT = [
  [/^(registry_|persist_|win_service|win_task)/, 'persist'],
  [/^(process_|remote_thread|image_load|driver_load|protect_block)/, 'proc'],
  [/^(file_|fim_)/, 'file'],
  [/^(network_|dns_)/, 'net'],
  [/^(win_logon|win_explicit|win_account|win_password|win_group|win_special|win_audit)/, 'account'],
  [/^win_ps_/, 'script'],
]
function catOf(e) {
  const t = String(e?.title || '')
  if (/IOC|情报/.test(t)) return 'ioc'
  if (/规则命中|行为序列|序列命中/.test(t)) return 'rule'
  const byMod = MODULE_CAT[String(e?.module || '').toLowerCase()]
  if (byMod) return byMod
  const m = String(e?.detail || '').match(/"etype":\s*"([a-z_]+)"/)
  if (m) {
    const hit = ETYPE_CAT.find(([re]) => re.test(m[1]))
    if (hit) return hit[1]
  }
  if (/注册表|持久化|服务安装|计划任务/.test(t)) return 'persist'
  if (/进程|注入|DLL|远程线程/.test(t)) return 'proc'
  if (/文件|FIM/.test(t)) return 'file'
  if (/外联|DNS|网络/.test(t)) return 'net'
  if (/登录|账号|密码|加入.*组|日志被清空/.test(t)) return 'account'
  if (/PowerShell|脚本/.test(t)) return 'script'
  return 'other'
}

const FOCUS_DEFS = [
  { key: 'persist', label: '持久化 / 注册表', short: '持', color: '#e11d2e' },
  { key: 'proc', label: '进程 / 注入 / DLL', short: '进', color: '#ff6a00' },
  { key: 'file', label: '文件落地', short: '文', color: '#d97706' },
  { key: 'net', label: '网络 / DNS', short: '网', color: '#0e7490' },
  { key: 'account', label: '账号与登录', short: '账', color: '#7a5af8' },
  { key: 'script', label: '脚本执行', short: '脚', color: '#2563eb' },
  { key: 'ioc', label: '威胁情报', short: '情', color: '#b42318' },
  { key: 'rule', label: '规则 / 序列', short: '规', color: '#475467' },
]
const focusCats = computed(() => FOCUS_DEFS.map((d) => {
  const list = allEvents.value.filter((e) => e.status !== 'ignored' && catOf(e) === d.key)
  return { ...d, count: list.length, hosts: new Set(list.map((e) => e.agent_id)).size }
}))

const liveAgo = computed(() => {
  void nowTick.value
  if (!lastSyncAt.value) return '等待同步'
  const s = Math.max(0, Math.floor((nowTick.value - lastSyncAt.value) / 1000))
  if (s < 3) return '刚刚'
  if (s < 60) return `${s}s 前`
  return `${Math.floor(s / 60)}m 前`
})

const childProcesses = computed(() => {
  if (module.value !== 'process' || !snapRow.value) return []
  const pid = Number(snapRow.value.pid)
  if (!pid) return []
  return (snap.value?.items || []).filter((r) => Number(r.ppid) === pid).slice(0, 24)
})

const eventAgents = computed(() => {
  const ids = new Set(filteredEvents.value.map((e) => e.agent_id))
  return agents.value.filter((a) => ids.has(a.agent_id))
})
const malwareFileStats = computed(() => {
  const list = events.value.filter(isMalwareFileEvent)
  return {
    total: list.length,
    hosts: new Set(list.map((e) => e.agent_id)).size,
    high: list.filter((e) => e.severity === 'critical' || e.severity === 'high').length,
  }
})
const eventFiltersActive = computed(() => {
  const on = eventFiltersOn.value || {}
  return Boolean(
    eventAgentId.value
    || focusKey.value
    || on.name || on.ioc || on.group || on.type || on.sev
    || (page.value === 'malware' && eventSevFilter.value),
  )
})
const filteredEvents = computed(() => {
  let list = [...events.value].filter((e) => e.status !== 'ignored')
  if (page.value === 'malware') list = list.filter(isMalwareFileEvent)
  if (eventAgentId.value) list = list.filter((e) => e.agent_id === eventAgentId.value)
  const on = eventFiltersOn.value || {}
  const typeKey = on.type || focusKey.value
  if (typeKey && page.value !== 'malware') list = list.filter((e) => catOf(e) === typeKey)
  const sev = on.sev || (page.value === 'malware' ? eventSevFilter.value : '')
  if (sev) list = list.filter((e) => e.severity === sev)
  if (on.group) {
    const g = (groupItems.value || []).find((x) => String(x.id) === String(on.group))
    const ids = new Set((g?.agent_ids || []).map(String))
    if (ids.size) list = list.filter((e) => ids.has(String(e.agent_id)))
    else list = []
  }
  if (on.name) {
    const q = on.name
    list = list.filter((e) => eventSearchText(e).includes(q))
  }
  if (on.ioc) {
    const q = on.ioc
    list = list.filter((e) => {
      const blob = eventIntelText(e)
      if (!blob.includes(q)) return false
      // 情报外联：优先 IOC / 网络类，也允许标题直接带该 IP/域名
      const c = catOf(e)
      return c === 'ioc' || c === 'net' || /IOC|情报|外联|DNS/i.test(String(e.title || ''))
    })
  }
  const { key, dir } = eventSort.value
  const sevRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
  list.sort((a, b) => {
    let av = a[key]
    let bv = b[key]
    if (key === 'severity') {
      av = sevRank[a.severity] || 0
      bv = sevRank[b.severity] || 0
    } else if (key === 'hit_count') {
      av = eventLogCount(a)
      bv = eventLogCount(b)
    }
    if (av === bv) return (b.id || 0) - (a.id || 0)
    if (av == null) return 1
    if (bv == null) return -1
    const cmp = av > bv ? 1 : -1
    return dir === 'asc' ? cmp : -cmp
  })
  return list
})
const evtPage = ref(1)
const evtPageSize = ref(20)
const evtPageCount = computed(() => Math.max(1, Math.ceil(filteredEvents.value.length / evtPageSize.value)))
const pagedEvents = computed(() => {
  const start = (evtPage.value - 1) * evtPageSize.value
  return filteredEvents.value.slice(start, start + evtPageSize.value)
})
watch([
  () => eventAgentId.value,
  () => focusKey.value,
  () => eventSevFilter.value,
  () => eventFiltersOn.value,
  () => eventSort.value.key,
  () => eventSort.value.dir,
], () => {
  evtPage.value = 1
})
watch(filteredEvents, () => {
  if (evtPage.value > evtPageCount.value) evtPage.value = evtPageCount.value
})
const allEventsSelected = computed(() => (
  pagedEvents.value.length > 0
  && pagedEvents.value.every((e) => selectedEventIds.value.includes(e.id))
))

function baseName(p) {
  const s = String(p || '')
  const i = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/'))
  return i >= 0 ? s.slice(i + 1) : s
}
const IOC_TYPE_CN = { ip: 'IP', domain: '域名', file_hash: '文件哈希', hash: '哈希', url: 'URL' }
const LOGON_TYPE_CN = { 2: '交互式', 3: '网络', 4: '批处理', 5: '服务', 7: '解锁', 8: '明文网络', 9: '新凭据', 10: '远程桌面', 11: '缓存' }
// 按事件类型给出：发起进程 → 威胁对象 → 匹配特征，以及侧栏「对象信息」行
function describeEvidence(ev) {
  if (!ev || typeof ev !== 'object') return null
  const et = String(ev.etype || '')
  const actorOf = (name, pid, path) => (name || pid ? { name: name || '', pid: pid ?? '', path: path || '' } : null)
  const row = (k, v, mono = false) => (v == null || v === '' ? null : { k, v: String(v), mono })
  const out = (o) => ({ ...o, rows: (o.rows || []).filter(Boolean) })
  const cmdExec = String(ev.command_line || ev.command || '').trim()
  const scriptBlock = String(ev.script_block || ev.payload || '').trim()
  const ruleHint = String(ev.rule_title || ev.rule_id || ev.rule_source || '')
  const scriptLike = /^win_ps_/.test(et)
    || (cmdExec && /powershell|pwsh|wscript|cscript|mshta|scriptblock|frombase64string|-enc\b|\.ps1|\.vbs/i.test(cmdExec))
    || (scriptBlock.length > 0)
  if (scriptLike && (cmdExec || scriptBlock || ev.rule_id || /EVM|LOLBin|规则命中/i.test(ruleHint))) {
    const body = scriptBlock || cmdExec
    const proc = ev.process_name || ev.name || baseName(ev.path || ev.image || parseExeFromCommandLine(cmdExec).path)
    return out({
      edge: scriptBlock ? '执行脚本' : '脚本/命令执行',
      title: proc || '脚本解释器',
      sub: body.slice(0, 160),
      matched: String(ev.matched || body).slice(0, 260),
      rows: [
        scriptBlock ? row('脚本块内容', scriptBlock, true) : null,
        cmdExec ? row('命令行', cmdExec, true) : null,
        row('匹配片段', ev.matched, true),
        row('规则', ev.rule_title || ev.rule_id),
        row('规则来源', ev.rule_source),
        row('进程', proc),
        row('路径', ev.path || ev.image, true),
        row('父进程', ev.parent_name),
        row('脚本路径', ev.path, true),
        row('脚本块 ID', ev.script_block_id, true),
        row('用户', ev.user),
      ],
    })
  }
  if (ev.ioc_value) {
    const fams = String(ev.malware || '').split(',').map((x) => x.trim()).filter(Boolean)
    return out({
      edge: '命中情报', actor: actorOf(ev.process_name, ev.pid, ev.path),
      title: ev.ioc_value, sub: `${IOC_TYPE_CN[ev.ioc_type] || ev.ioc_type || 'IOC'}${fams.length ? ` · ${fams.slice(0, 3).join(', ')}${fams.length > 3 ? ' 等' : ''}` : ''}`,
      matched: `${ev.ioc_type || 'ioc'}=${ev.ioc_value}`,
      rows: [row('情报值', ev.ioc_value, true), row('情报类型', IOC_TYPE_CN[ev.ioc_type] || ev.ioc_type), row('恶意家族', ev.malware),
        row('情报来源', ev.intel_source), row('触发事件', ev.trigger), row('发起进程', ev.process_name), row('远程', ev.remote, true), row('域名', ev.domain || ev.query, true)],
    })
  }
  if (/^(remote_thread|process_access)/.test(et)) {
    const src = baseName(ev.path) || ev.process_name || ''
    const dst = baseName(ev.target_path) || (ev.target_pid ? `PID ${ev.target_pid}` : '目标进程')
    return out({
      edge: et.startsWith('process_access') ? '打开进程' : '远程线程', actor: actorOf(src, ev.pid, ev.path),
      title: dst, sub: ev.target_path || '', meta: [ev.target_pid ? { k: 'PID', v: ev.target_pid } : null, ev.access ? { k: '权限', v: ev.access } : null, ev.start_address ? { k: '起始地址', v: ev.start_address } : null].filter(Boolean),
      matched: `${src} → ${dst}${ev.access ? ` (${ev.access})` : ''}`,
      rows: [row('源进程', ev.path || src, true), row('目标进程', ev.target_path || dst, true), row('目标 PID', ev.target_pid), row('访问权限', ev.access, true), row('起始地址', ev.start_address, true), row('调用栈', ev.call_trace, true)],
    })
  }
  if (/^network_/.test(et)) {
    const target = ev.domain || ev.remote || ev.remote_ip || ''
    return out({
      edge: '外联', actor: actorOf(ev.process_name, ev.pid),
      title: target || '远程地址', sub: ev.domain ? (ev.remote || '') : (ev.proto || ''),
      matched: ev.domain ? `${ev.domain} (${ev.remote || ev.remote_ip || ''})` : (ev.remote || ''),
      rows: [row('进程', ev.process_name), row('远程', ev.remote || ev.remote_ip, true), row('域名', ev.domain, true), row('本地', ev.local, true), row('协议', ev.proto)],
    })
  }
  if (et === 'dns_nx_burst') {
    const s = Array.isArray(ev.samples) ? ev.samples : []
    return out({
      edge: 'DNS 解析', actor: actorOf(ev.process_name, ev.pid),
      title: `${ev.nx_count || s.length} 个域名解析失败`, sub: s.slice(0, 3).join(', '),
      matched: s.slice(0, 5).join(', '),
      rows: [row('进程', ev.process_name), row('失败数', ev.nx_count), row('统计窗口(秒)', ev.window_sec), row('样本域名', s.join(', '), true)],
    })
  }
  if (/^dns_/.test(et)) {
    const ans = Array.isArray(ev.answers) ? ev.answers.join(', ') : ev.answers
    return out({
      edge: 'DNS 解析', actor: actorOf(ev.process_name, ev.pid),
      title: ev.query || ev.domain || '域名', sub: [ev.status_name, ans].filter(Boolean).join(' · '),
      matched: ev.query || ev.domain || '',
      rows: [row('查询域名', ev.query || ev.domain, true), row('记录类型', ev.qtype_name || ev.type), row('结果', ev.status_name), row('解析地址', ans, true), row('DGA 分数', ev.dga_score), row('进程', ev.process_name)],
    })
  }
  if (/^(image_load|driver_load)/.test(et)) {
    return out({
      edge: et.startsWith('driver') ? '加载驱动' : '加载', actor: et.startsWith('driver') ? null : actorOf(ev.host_process || ev.process_name, ev.pid),
      title: ev.name || ev.module_name || baseName(ev.path), sub: ev.path || ev.image || '',
      matched: ev.path || ev.image || '',
      rows: [row('模块', ev.name || ev.module_name), row('路径', ev.path || ev.image, true), row('签名', ev.signed), row('签名者', ev.signer), row('宿主进程', ev.host_process || ev.process_name)],
    })
  }
  if (/^(file_|fim_)/.test(et)) {
    const taskExe = ev.task_execute || ev.payload_path || ev.shortcut_target || ev.shortcut_url
    const taskDef = ev.task_def_path || (String(ev.label || '').includes('计划') ? ev.path : '')
    const title = taskExe ? baseName(taskExe) : (ev.name || baseName(ev.path))
    const matched = taskExe || ev.matched || ev.path || ''
    return out({
      edge: /delete/.test(et) ? '删除' : (/modify|rename/.test(et) ? '修改' : '创建'), actor: actorOf(ev.process_name, ev.pid),
      title,
      sub: taskExe ? `${taskExe}${ev.task_workdir || ev.shortcut_workdir ? ' · ' + (ev.task_workdir || ev.shortcut_workdir) : ''}` : (ev.path || ''),
      matched,
      rows: [
        row('任务载荷', ev.task_execute, true),
        row('快捷方式目标', ev.shortcut_target || ev.shortcut_url, true),
        row('快捷方式路径', ev.shortcut_path, true),
        row('工作目录', ev.task_workdir || ev.shortcut_workdir || ev.working_directory, true),
        row('命令行', ev.task_command_line || ev.command_line, true),
        row('脚本摘要', ev.script_snippet, true),
        row('可疑关键词', Array.isArray(ev.script_suspicious) ? ev.script_suspicious.join(', ') : ev.script_suspicious),
        row('任务定义文件', taskDef || (ev.task_name ? ev.path : ''), true),
        row('任务名', ev.task_name),
        row('文件', ev.name || baseName(ev.path)),
        row('路径', ev.path, true),
        row('进程', ev.process_name),
        row('SHA256', ev.sha256, true),
        row('原 SHA256', ev.old_sha256, true),
        row('大小', ev.size),
        row('原大小', ev.old_size),
      ],
    })
  }
  if (et === 'win_task_create' || et === 'win_task_update' || et === 'win_task_ops') {
    const taskExe = ev.task_execute || ev.payload_path
    return out({
      edge: et === 'win_task_create' ? '创建计划任务' : (et === 'win_task_update' ? '更新计划任务' : '计划任务操作'),
      title: taskExe ? baseName(taskExe) : (ev.task_name || ev.task || '计划任务'),
      sub: ev.task_command_line || ev.command_line || '',
      matched: taskExe || ev.task || '',
      rows: [
        row('任务载荷', taskExe, true),
        row('工作目录', ev.task_workdir, true),
        row('命令行', ev.task_command_line, true),
        row('任务名', ev.task_name || ev.task),
        row('定义路径', ev.task_def_path, true),
      ],
    })
  }
  if (et === 'win_bits') {
    return out({
      edge: 'BITS 传输',
      title: baseName(ev.local_path) || ev.job_name || 'BITS',
      sub: ev.remote_url || ev.local_path || '',
      matched: ev.matched || ev.remote_url || ev.local_path || '',
      rows: [
        row('任务名', ev.job_name),
        row('远程 URL', ev.remote_url, true),
        row('本地路径', ev.local_path, true),
        row('所有者', ev.owner),
      ],
    })
  }
  if (et === 'win_smb') {
    return out({
      edge: 'SMB 访问',
      title: ev.share || ev.path || 'SMB',
      sub: ev.user || '',
      matched: ev.matched || ev.share || '',
      rows: [row('共享', ev.share, true), row('路径', ev.path, true), row('用户', ev.user), row('状态', ev.status)],
    })
  }
  if (/^wmi_persist_/.test(et)) {
    const payload = ev.task_execute || ev.payload_path || ev.command_line
    return out({
      edge: et.includes('delete') ? '删除 WMI 订阅' : (et.includes('modify') ? '修改 WMI 订阅' : '新增 WMI 订阅'),
      title: baseName(payload) || ev.consumer || 'WMI',
      sub: ev.command_line || ev.script_text || '',
      matched: payload || '',
      rows: [
        row('载荷', payload, true),
        row('命令行', ev.command_line, true),
        row('脚本', ev.script_text, true),
        row('Filter', ev.filter),
        row('Consumer', ev.consumer),
        row('类型', ev.consumer_type),
        row('WQL', ev.wmi_query, true),
      ],
    })
  }
  if (et === 'registry_write') {
    return out({
      edge: '写入注册表', actor: actorOf(ev.process_name, ev.pid),
      title: baseName(ev.path), sub: ev.path || '', meta: ev.value ? [{ k: '值', v: String(ev.value).slice(0, 48) }] : [],
      matched: `${ev.path || ''}${ev.value ? ` = ${ev.value}` : ''}`,
      rows: [row('注册表路径', ev.path, true), row('写入值', ev.value, true), row('进程', ev.process_name)],
    })
  }
  if (/^win_(account|password)/.test(et)) {
    return out({
      edge: et === 'win_account_create' ? '创建账号' : (et === 'win_password_reset' ? '重置密码' : '启用账号'),
      title: ev.user || '账号', sub: ev.by ? `操作者 ${ev.by}` : '', matched: `user=${ev.user || ''}`,
      rows: [row('账号', ev.user), row('操作者', ev.by)],
    })
  }
  if (et === 'win_group_add') {
    return out({
      edge: '加入组', title: `${ev.member || '成员'} → ${ev.group || '组'}`, sub: ev.group ? `组 ${ev.group}` : '',
      matched: `${ev.member || ''} → ${ev.group || ''}`, rows: [row('成员', ev.member, true), row('组', ev.group)],
    })
  }
  if (/^win_(logon|explicit_logon)/.test(et)) {
    const lt = ev.logon_type ? `${LOGON_TYPE_CN[ev.logon_type] || ''}(${ev.logon_type})` : ''
    return out({
      edge: et === 'win_logon_fail' ? '登录失败' : '登录', actor: ev.process ? actorOf(baseName(ev.process), '', ev.process) : null,
      title: ev.user || '账号', sub: [ev.ip ? `来源 ${ev.ip}` : '', lt, ev.target ? `目标 ${ev.target}` : ''].filter(Boolean).join(' · '),
      matched: `user=${ev.user || ''}${ev.ip ? ` ip=${ev.ip}` : ''}`,
      rows: [row('账号', ev.domain ? `${ev.domain}\\${ev.user}` : ev.user), row('来源 IP', ev.ip, true), row('登录类型', lt), row('状态码', ev.status, true), row('子状态码', ev.substatus, true), row('目标服务器', ev.target), row('进程', ev.process, true)],
    })
  }
  if (et === 'win_special_priv') {
    return out({ edge: '特权分配', title: ev.user || '账号', sub: ev.privileges || '', matched: ev.privileges || '', rows: [row('账号', ev.user), row('特权', ev.privileges, true)] })
  }
  if (/^win_service/.test(et)) {
    return out({
      edge: et === 'win_service_install' ? '安装服务' : '服务变更', title: ev.name || '服务', sub: ev.path || [ev.from, ev.to].filter(Boolean).join(' → ') || ev.state || '',
      matched: ev.path || ev.name || '',
      rows: [row('服务名', ev.name), row('映像路径', ev.path, true), row('运行账户', ev.account), row('启动类型', ev.start_type), row('原启动类型', ev.from), row('新启动类型', ev.to), row('状态', ev.state)],
    })
  }
  if (/^win_task/.test(et)) {
    const xml = String(ev.content || '')
    const cmd = (xml.match(/<Command>([^<]+)<\/Command>/i) || [])[1] || ''
    const args = (xml.match(/<Arguments>([^<]+)<\/Arguments>/i) || [])[1] || ''
    return out({
      edge: et === 'win_task_create' ? '创建任务' : '更新任务', title: ev.task || '计划任务', sub: [cmd, args].filter(Boolean).join(' '),
      matched: cmd || ev.task || '',
      rows: [row('任务', ev.task), row('执行程序', cmd, true), row('参数', args, true), row('任务定义', xml, true)],
    })
  }
  if (/^win_ps_/.test(et)) {
    const sb = String(ev.script_block || ev.payload || '')
    return out({
      edge: '执行脚本', title: et === 'win_ps_module' ? 'PowerShell 模块日志' : 'PowerShell 脚本块', sub: sb.slice(0, 120),
      matched: sb.slice(0, 200),
      rows: [row('脚本内容', sb, true), row('脚本路径', ev.path, true), row('脚本块 ID', ev.script_block_id, true)],
    })
  }
  if (et === 'win_audit_clear') {
    return out({ edge: '清空日志', title: 'Windows 安全日志', sub: `日志被清空（事件 ${ev.event_id || 1102}）`, matched: `event_id=${ev.event_id || 1102}`, rows: [row('日志通道', ev.channel || 'Security'), row('事件 ID', ev.event_id)] })
  }
  if (Array.isArray(ev.failed) && ev.failed.length) {
    const names = ev.failed.map((f) => f.title || f.id).filter(Boolean).join('；')
    return out({
      edge: '合规检查',
      title: `SCA ${ev.count || ev.failed.length} 项未通过`,
      sub: names.slice(0, 160),
      matched: ev.matched || names,
      rows: ev.failed.slice(0, 12).map((f) => row(f.title || f.id, `${f.status || 'fail'} · ${f.id || ''}`.trim())),
    })
  }
  if (et === 'ptm_hit' || et === 'evm_hit') {
    const chain = Array.isArray(ev.chain) ? ev.chain : []
    const trigger = ev.trigger && typeof ev.trigger === 'object' ? ev.trigger : null
    const chunks = chain.length ? chain : (trigger ? [trigger] : [])
    const first = chunks[0] || ev
    const matched = String(ev.matched || '').trim()
      || chunks.map((c, i) => {
        const s = c.summary || c.etype || ''
        const rk = c.reg_key || c.key || c.path || ''
        return `${i + 1}) ${rk && !String(s).includes(rk) ? `${rk} ${s}` : (s || rk)}`.trim()
      }).filter(Boolean).join(' | ')
      || String(ev.source_summary || first.summary || '')
    const regPath = first.reg_key || first.key || (String(first.etype || '').startsWith('registry') ? first.path : '')
    return out({
      edge: et === 'ptm_hit' ? '行为序列 PTM' : '规则命中 EVM',
      title: ev.rule_title || ev.title || '检测规则',
      sub: matched.slice(0, 200),
      matched,
      rows: [
        row('规则 ID', ev.rule_id, true),
        row('规则标题', ev.rule_title || ev.title),
        row('规则来源', ev.rule_source),
        row('来源事件类型', ev.source_etype || first.etype),
        row('时间线摘要', ev.source_summary || first.summary),
        row('注册表路径', regPath, true),
        row('值名称', first.value_name, true),
        row('值内容', first.value, true),
        row('进程', first.name || first.process_name),
        row('PID', first.pid),
        row('命令行', first.command_line || ev.command_line, true),
        row('远程地址', first.remote || first.remote_ip || ev.remote, true),
        row('域名', first.domain || ev.domain, true),
        row('本地地址', first.local || ev.local, true),
        row('协议', first.proto || ev.proto),
        row('路径', first.path || ev.path, true),
        ...(chunks.length > 1
          ? chunks.flatMap((c, i) => [
            row(`序列 ${i + 1} 类型`, c.etype),
            row(`序列 ${i + 1} 摘要`, c.summary),
            row(`序列 ${i + 1} 对象`, c.reg_key || c.key || c.path || c.remote, true),
          ])
          : []),
      ],
    })
  }
  if (/^persist_|^registry_/.test(et) || ev.reg_key || ev.key || ev.value_name) {
    const key = ev.key || ev.reg_key || ''
    const vn = ev.value_name || (key.includes('\\') ? key.slice(key.lastIndexOf('\\') + 1) : '')
    const matched = String(ev.matched || '').trim()
      || (key && ev.value != null && ev.value !== '' ? `${key} = ${ev.value}` : '')
      || key
      || String(ev.summary || '')
    return out({
      edge: /delete/.test(et) ? '删除持久化' : (/modify|set|write/.test(et) ? '修改持久化' : '新增持久化'),
      title: ev.label || vn || '持久化项',
      sub: matched.slice(0, 200),
      matched,
      rows: [
        row('监控点', ev.label),
        row('注册表键', key, true),
        row('值名称', vn || ev.value_name),
        row('写入值', ev.value, true),
        row('旧值', ev.old_value, true),
        row('Hive', ev.hive),
        row('变更', ev.change),
        row('摘要', ev.summary || ev.source_summary),
        row('关联进程', ev.process_name || ev.name),
        row('PID', ev.pid),
        row('命令行', ev.command_line, true),
      ],
    })
  }
  if (et === 'building_block_upgrade' || ev.building_block_upgrade) {
    const related = Array.isArray(ev.related_hits) ? ev.related_hits : []
    const rules = Array.isArray(ev.distinct_rules) ? ev.distinct_rules : []
    const matched = String(ev.matched || '').trim()
      || related.map((x) => x.title || x.rule_id || x.summary).filter(Boolean).join('；')
      || rules.join('；')
    return out({
      edge: '多阶段关联',
      title: `命中 ${rules.length || related.length || '?'} 条积木/关联`,
      sub: matched.slice(0, 200),
      matched,
      rows: [
        row('统计窗口(秒)', ev.window_sec),
        row('战术', Array.isArray(ev.tactics) ? ev.tactics.join(', ') : ev.tactics),
        row('规则列表', rules.join(', '), true),
        row('研判提示', ev.investigation),
        row('风险分', ev.risk_score),
        ...related.slice(0, 8).flatMap((x, i) => [
          row(`子告警 ${i + 1}`, x.title || x.rule_id),
          row(`子告警 ${i + 1} 摘要`, x.summary || x.command_line || x.path || x.remote, true),
          row(`子告警 ${i + 1} 进程`, x.process_name || (x.pid != null ? `PID ${x.pid}` : '')),
        ]),
      ],
    })
  }
  return null
}
function buildMatchedHint(raw) {
  if (!raw || typeof raw !== 'object') return ''
  if (raw.matched) return String(raw.matched)
  const desc = describeEvidence(raw)
  if (desc?.matched) return desc.matched
  // 注册表
  if (raw.key || raw.reg_key || raw.value_name) {
    const parts = []
    const keyPart = String(raw.reg_key || raw.key || '')
    if (raw.hive && !keyPart.toUpperCase().startsWith(`${String(raw.hive).toUpperCase()}\\`)) parts.push(String(raw.hive))
    if (keyPart) parts.push(keyPart)
    const base = parts.filter(Boolean).join('\\')
    const vn = raw.value_name ? String(raw.value_name) : ''
    const val = raw.value != null && raw.value !== '' ? String(raw.value) : ''
    if (vn && val) return `${base || raw.key || ''} → ${vn}=${val}`
    if (vn) return `${base || raw.key || ''} → ${vn}`
    if (val) return `${base || raw.key || ''} = ${val}`
    return base || String(raw.key || '')
  }
  return String(raw.path || raw.name || raw.image || raw.command_line || raw.query || raw.domain || '')
}
function fallbackEvidenceFromTitle(title) {
  const t = String(title || '')
  let m = t.match(/^注册表[^:：]*[:：]\s*(.+)$/i)
  if (m) {
    const key = m[1].replace(/（Agent 离线期间）$/, '').trim()
    const vn = key.includes('\\') ? key.slice(key.lastIndexOf('\\') + 1) : key
    return {
      etype: 'registry_set', key, reg_key: key, value_name: vn, label: '注册表',
      source: 'title_fallback',
    }
  }
  m = t.match(/^持久化[^:：]*[:：]\s*(.+)$/i)
  if (m) {
    const key = m[1].replace(/（Agent 离线期间）$/, '').trim()
    const vn = key.includes('\\') ? key.slice(key.lastIndexOf('\\') + 1) : key
    return {
      etype: 'persist_add', key, reg_key: key, value_name: vn, label: '持久化',
      source: 'title_fallback',
    }
  }
  return null
}
function hydratePersistFields(raw) {
  if (!raw || typeof raw !== 'object') return raw
  const out = { ...raw }
  if (!(out.key || out.reg_key)) {
    const fromSummary = String(out.summary || out.source_summary || out.matched || '')
    let m = fromSummary.match(/(?:持久化(?:新增|修改|删除)|注册表)[^:：]*[:：]\s*([^\s·]+)/i)
    if (!m) m = fromSummary.match(/\b((?:HK(?:LM|CU|CR|U|CC)|HKEY_[A-Z_]+)\\[^\s·=]+)/i)
    if (m) {
      const key = m[1].replace(/（Agent 离线期间）$/, '').trim()
      out.key = out.key || key
      out.reg_key = out.reg_key || key
      if (!out.value_name && key.includes('\\')) out.value_name = key.slice(key.lastIndexOf('\\') + 1)
      if (!out.label) out.label = '持久化'
    }
  }
  if (!out.matched) out.matched = buildMatchedHint(out)
  if (!out.etype && (out.building_block_upgrade || out.related_hits)) out.etype = 'building_block_upgrade'
  return out
}
function parseEventEvidence(e) {
  if (!e) return {}
  let raw = null
  if (e.detail_obj && typeof e.detail_obj === 'object') raw = e.detail_obj
  else {
    try {
      if (String(e.detail || '').startsWith('{')) raw = JSON.parse(e.detail)
    } catch { /* JSON 被截断时走标题兜底 */ }
  }
  if (!raw || typeof raw !== 'object' || (!raw.evidence && !raw.key && !raw.path && !raw.name && !raw.reg_key && !raw.value_name && !raw.etype
    && !raw.rule_id && !raw.chain && !raw.matched && !raw.source_summary && !raw.source_etype
    && !raw.summary && !raw.building_block_upgrade && !raw.related_hits && !raw.distinct_rules)) {
    const fb = fallbackEvidenceFromTitle(e.title)
    if (fb) {
      return { ...fb, evidence: fb, matched: buildMatchedHint(fb) }
    }
    if (!raw || typeof raw !== 'object') return {}
  }
  // 时间线晋升 / 传感器：字段在顶层；规则命中：嵌在 evidence
  if (!raw.evidence) {
    const hydrated = hydratePersistFields(raw)
    const matched = buildMatchedHint(hydrated)
    return { ...hydrated, evidence: hydrated, matched: matched || hydrated.matched || '' }
  }
  raw = hydratePersistFields(raw)
  if (!raw.matched) {
    return { ...raw, matched: buildMatchedHint(raw.evidence) || buildMatchedHint(raw) }
  }
  if (!raw.command_line && Array.isArray(raw.chain)) {
    for (let i = raw.chain.length - 1; i >= 0; i--) {
      const c = raw.chain[i]
      if (c?.command_line) {
        raw.command_line = c.command_line
        break
      }
    }
  }
  return raw
}
function evidenceFlatOf(root) {
  const r = root || {}
  return r.evidence && typeof r.evidence === 'object' ? r.evidence : r
}

function fileBaseName(p) {
  const s = String(p || '').trim()
  if (!s) return ''
  const i = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/'))
  return i >= 0 ? s.slice(i + 1) : s
}

/** 从 detail / chain / 脚本块 / 匹配特征 解析可展示的完整命令行 */
function eventCmdSummary(e) {
  if (!e) return ''
  const root = parseEventEvidence(e)
  const flat = evidenceFlatOf(root)
  const cmd = resolveCommandLine(flat, root)
  if (!cmd) return ''
  return cmd.length > 72 ? `${cmd.slice(0, 72)}…` : cmd
}

function detailLooksThinForEnrich(e) {
  const root = parseEventEvidence(e)
  const flat = evidenceFlatOf(root)
  if (resolveCommandLine(flat, root)) return false
  if (Array.isArray(flat.chain) && flat.chain.length) return false
  if (Array.isArray(root?.chain) && root.chain.length) return false
  const m = String(flat.matched || root?.matched || '')
  return m.length < 12
}

function resolveCommandLine(flat, root) {
  const f = flat || {}
  const r = root || {}
  const direct = String(
    f.command_line || f.command || f.execute || r.command_line || r.command || r.execute || '',
  ).trim()
  if (direct) return direct
  const evd = f.evidence && typeof f.evidence === 'object' ? f.evidence : (r.evidence && typeof r.evidence === 'object' ? r.evidence : null)
  if (evd) {
    const ec = String(evd.command_line || evd.command || evd.execute || '').trim()
    if (ec) return ec
  }
  const chain = Array.isArray(f.chain) ? f.chain : (Array.isArray(r.chain) ? r.chain : [])
  for (let i = chain.length - 1; i >= 0; i--) {
    const c = chain[i]
    if (!c || typeof c !== 'object') continue
    const cmd = String(c.command_line || c.command || '').trim()
    if (cmd) return cmd
  }
  const script = String(f.script_block || f.payload || r.script_block || r.payload || '').trim()
  if (script) return script
  const regVal = String(f.value || r.value || '').trim()
  if (regVal && (f.reg_key || f.key || r.reg_key) && /\\|\//.test(regVal)) {
    return regVal
  }
  const matched = String(f.matched || r.matched || '').trim()
  if (matched.length > 24 && /powershell|cmd\.exe|wscript|\.exe\s| -enc|-e\s|-c\s|frombase64/i.test(matched)) {
    return matched
  }
  return ''
}

function parseExeFromCommandLine(cmd) {
  const s = String(cmd || '').trim()
  if (!s) return { path: '', name: '' }
  let m = s.match(/"([A-Za-z]:\\[^"]+\.(?:exe|dll|bat|cmd|ps1|scr|hta|msi))"/i)
  if (m) return { path: m[1], name: fileBaseName(m[1]) }
  m = s.match(/'([A-Za-z]:\\[^']+\.(?:exe|dll|bat|cmd|ps1|scr|hta|msi))'/i)
  if (m) return { path: m[1], name: fileBaseName(m[1]) }
  m = s.match(/([A-Za-z]:\\[^\s"']+\.(?:exe|dll|bat|cmd|ps1|scr|hta|msi))/i)
  if (m) return { path: m[1], name: fileBaseName(m[1]) }
  return { path: '', name: '' }
}

function parsePathsFromMatched(matched) {
  const s = String(matched || '')
  const out = []
  const re = /"([A-Za-z]:\\[^"]+)"|'([A-Za-z]:\\[^']+)'|([A-Za-z]:\\[^\s"']+)/g
  let m
  while ((m = re.exec(s)) !== null) {
    const p = (m[1] || m[2] || m[3] || '').trim()
    if (p && !out.includes(p)) out.push(p)
  }
  return out
}

function nameFromEventTitle(title) {
  const t = String(title || '').trim()
  const m = t.match(/LOLBin\s*[·•]\s*(\S+)/i) || t.match(/规则命中[：:]\s*(.+)/)
  if (m) {
    const seg = m[1].split(/\s+/)[0]
    if (/\.exe$/i.test(seg)) return seg
    if (seg && seg.length <= 24) return `${seg}.exe`
  }
  const art = eventTitleArtifact(t)
  if (art && /\.(exe|dll|bat|cmd|ps1)$/i.test(art)) return art
  return ''
}

function pickProcessSnapFields(row) {
  if (!row || typeof row !== 'object') return {}
  return {
    name: row.name,
    process_name: row.name || row.process_name,
    path: row.path || row.image,
    image: row.path || row.image,
    signed: row.signed,
    signer: row.signer,
    company: row.company,
    sha256: row.sha256,
    ext: row.ext,
    size_kb: row.size_kb ?? row.size,
    user: row.user,
    command_line: row.command_line || row.command,
    parent_name: row.parent_name,
    ppid: row.ppid,
    create_time: row.create_time || row.first_seen,
  }
}

function mergeThreatEvidenceEnrich(partial) {
  if (!partial || typeof partial !== 'object') return
  const cur = threatEvidenceEnrich.value || {}
  const next = { ...cur }
  let changed = false
  for (const [k, v] of Object.entries(partial)) {
    if (v == null || v === '') continue
    if (next[k] === v) continue
    next[k] = v
    changed = true
  }
  if (changed) threatEvidenceEnrich.value = next
}

async function enrichThreatFromProcessDb(agentId, flat) {
  const aid = String(agentId || '').trim()
  if (!aid || !flat) return
  const pid = flat.pid != null && flat.pid !== '' ? String(flat.pid) : ''
  const ppid = flat.ppid != null && flat.ppid !== '' ? String(flat.ppid) : ''
  try {
    if (pid) {
      const r = await listProcessEntities(aid, { q: pid })
      const items = r?.items || []
      const hit = items.find((row) => String(row.pid) === pid) || items[0]
      if (hit) mergeThreatEvidenceEnrich(pickProcessSnapFields(hit))
    }
    if (ppid) {
      const r = await listProcessEntities(aid, { q: ppid })
      const items = r?.items || []
      const par = items.find((row) => String(row.pid) === ppid) || items[0]
      if (par?.name) mergeThreatEvidenceEnrich({ parent_name: par.name })
    }
  } catch { /* 实体表未同步时忽略 */ }
}

function enrichEvidenceFlat(flat, root, event, enrich, tree) {
  const out = { ...(flat || {}) }
  const nested = root?.evidence && typeof root.evidence === 'object' ? root.evidence : {}
  for (const [k, v] of Object.entries(nested)) {
    if ((out[k] == null || out[k] === '') && v != null && v !== '') out[k] = v
  }
  for (const k of [
    'rule_id', 'rule_title', 'rule_source', 'matched', 'etype', 'module', 'event_ts', 'ts',
    'command_line', 'command', 'execute', 'working_directory', 'triggers', 'task_name',
    'task_execute', 'task_command_line', 'task_workdir', 'task_arguments', 'payload_path', 'task_def_path',
    'shortcut_path', 'shortcut_target', 'shortcut_url', 'shortcut_workdir', 'script_snippet',
    'remote_url', 'local_path', 'job_name', 'share', 'filter', 'consumer', 'wmi_query',
    'name', 'process_name', 'path', 'image', 'process_path', 'parent_name', 'ppid',
    'user', 'summary', 'script_block', 'script_block_id', 'payload', 'value', 'reg_key', 'key',
  ]) {
    if ((out[k] == null || out[k] === '') && root?.[k] != null && root[k] !== '') out[k] = root[k]
  }
  const cmd = out.command_line || out.command || ''
  const exe = parseExeFromCommandLine(cmd)
  const matchedPaths = parsePathsFromMatched(root?.matched || out.matched || '')
  const taskPayload = out.task_execute || out.payload_path || out.execute
  if (taskPayload && /^(file_|fim_)/.test(String(out.etype || root?.etype || ''))) {
    out.payload_path = out.payload_path || taskPayload
    out.path = out.path || taskPayload
    out.image = out.image || taskPayload
    if (!out.command_line && out.task_command_line) out.command_line = out.task_command_line
    if (!out.working_directory && out.task_workdir) out.working_directory = out.task_workdir
  }
  if (!out.path && !out.image) {
    out.path = exe.path || matchedPaths[0] || out.path
  }
  if (!out.image && out.path) out.image = out.path
  const procName = out.process_name || out.name || (taskPayload ? baseName(taskPayload) : '') || exe.name || nameFromEventTitle(event?.title)
  if (procName) {
    out.process_name = procName
    out.name = out.name || procName
  }
  const parent = resolveParentInfo(out, event?.agent_id, threatProcessSnap.value)
  if (!out.parent_name && parent.name) out.parent_name = parent.name
  if ((out.ppid == null || out.ppid === '') && parent.ppid != null && parent.ppid !== '') out.ppid = parent.ppid
  const hitId = tree?.hit_id
  const hitNode = (tree?.nodes || []).find((n) => n.id === hitId)
  if (hitNode) {
    if (!out.name) out.name = hitNode.name
    if (!out.process_name) out.process_name = hitNode.name
    if (!out.path && hitNode.path) out.path = hitNode.path
    if (!out.command_line && hitNode.command_line) out.command_line = hitNode.command_line
    if (out.pid == null || out.pid === '') out.pid = hitNode.pid
  }
  if (enrich && typeof enrich === 'object') {
    for (const [k, v] of Object.entries(enrich)) {
      if ((out[k] == null || out[k] === '') && v != null && v !== '') out[k] = v
    }
  }
  const resolvedCmd = resolveCommandLine(out, root)
  if (resolvedCmd && !out.command_line) out.command_line = resolvedCmd
  if (!out.etype) {
    if (out.building_block_upgrade || root?.building_block_upgrade || Array.isArray(out.related_hits) || Array.isArray(root?.related_hits)) {
      out.etype = 'building_block_upgrade'
    } else if (out.key || out.reg_key || out.value_name || root?.key || root?.reg_key) {
      out.etype = out.etype || root?.etype || 'persist_add'
    } else {
      out.etype = nested.etype || root?.etype || listInferredEtype.value || ''
    }
  }
  if (!(out.key || out.reg_key) && (out.summary || root?.summary || out.matched)) {
    const hydrated = hydratePersistFields({ ...out, summary: out.summary || root?.summary, matched: out.matched || root?.matched })
    if (hydrated.key || hydrated.reg_key) {
      out.key = out.key || hydrated.key
      out.reg_key = out.reg_key || hydrated.reg_key
      out.value_name = out.value_name || hydrated.value_name
      out.label = out.label || hydrated.label
      out.matched = out.matched || hydrated.matched
      if (!out.etype) out.etype = hydrated.etype || 'persist_add'
    }
  }
  if (!out.ext && out.path) {
    const em = String(out.path).match(/\.([a-z0-9]{1,8})$/i)
    if (em) out.ext = em[1].toLowerCase()
  }
  return out
}
function evidencePathOf(flat, root) {
  const ev = flat || {}
  const et = String(ev.etype || root?.etype || '')
  // 网络 / DNS：路径只取进程镜像，不要把 local/远程 IP 当成路径
  if (/^network_|^dns_/.test(et) || (ev.remote || ev.remote_ip || ev.domain) && !ev.path && !ev.image) {
    return ev.path || ev.image || ev.process_path || ''
  }
  if (/^(file_|fim_)/.test(et) && (ev.payload_path || ev.task_execute)) {
    return ev.payload_path || ev.task_execute || ev.path || ''
  }
  return ev.path || ev.image || ev.process_path || ev.key || ev.reg_key
    || ev.TargetFilename || ev.command || ''
}
function evidenceNameOf(flat, path) {
  const ev = flat || {}
  if (ev.name || ev.task_name || ev.display_name || ev.module_name || ev.value_name || ev.label) {
    return ev.name || ev.task_name || ev.display_name || ev.module_name || ev.value_name || ev.label
  }
  const p = path
  if (!p) return ''
  const s = String(p).replace(/\\/g, '/')
  const i = s.lastIndexOf('/')
  return i >= 0 ? s.slice(i + 1) : s
}

/** 威胁预览：解析事件时间（无效则 NaN，避免误把同主机全部告警算关联） */
function eventTimeMs(e) {
  if (!e) return NaN
  const raw = e.updated_at ?? e.created_at ?? e.ts ?? ''
  if (typeof raw === 'number' && Number.isFinite(raw)) return raw
  const s = String(raw || '').trim()
  if (!s) return NaN
  let t = Date.parse(s.includes('T') ? s : s.replace(' ', 'T'))
  if (!Number.isFinite(t)) t = Date.parse(s)
  return Number.isFinite(t) ? t : NaN
}

/** 标题中「·」后的对象名，或末尾文件名（用于同进程/同样本关联） */
function eventTitleArtifact(title) {
  const t = String(title || '').trim()
  const parts = t.split('·').map((s) => s.trim()).filter(Boolean)
  if (parts.length >= 2) {
    const last = parts[parts.length - 1]
    if (last.length >= 2) return last.toLowerCase()
  }
  const m = t.match(/[·:：]\s*([^\s·:：]{2,120})\s*$/)
  return m ? m[1].toLowerCase() : ''
}

function registryKeyOf(flat, raw) {
  const ev = flat || {}
  return String(ev.key || ev.reg_key || raw?.key || raw?.reg_key || '').trim().toLowerCase()
}

const RELATED_EVENT_MIN_SCORE = 55
const RELATED_EVENT_MAX = 5

function relatedEventScore(cur, e, windowMs = 2 * 60 * 60 * 1000) {
  if (!cur?.agent_id || !e?.agent_id) return -1
  if (String(e.id) === String(cur.id)) return -1
  if (e.agent_id !== cur.agent_id) return -1

  const curRaw = parseEventEvidence(cur)
  const eRaw = parseEventEvidence(e)
  const curFlat = evidenceFlatOf(curRaw)
  const eFlat = evidenceFlatOf(eRaw)

  let strong = false
  let score = 0

  const curRule = String(curRaw.rule_id || curFlat.rule_id || '').trim()
  const eRule = String(eRaw.rule_id || eFlat.rule_id || '').trim()
  if (curRule && eRule && curRule === eRule) {
    strong = true
    score += 100
  }

  const pCur = String(evidencePathOf(curFlat, curRaw) || '').trim().toLowerCase()
  const pE = String(evidencePathOf(eFlat, eRaw) || '').trim().toLowerCase()
  if (pCur && pE) {
    if (pCur === pE) {
      strong = true
      score += 80
    } else if (pCur.length > 10 && pE.length > 10 && (pCur.includes(pE) || pE.includes(pCur))) {
      strong = true
      score += 55
    }
  }

  const pidCur = curFlat.pid != null && curFlat.pid !== '' ? String(curFlat.pid) : ''
  const pidE = eFlat.pid != null && eFlat.pid !== '' ? String(eFlat.pid) : ''
  if (pidCur && pidE && pidCur === pidE) {
    strong = true
    score += 70
  }

  const artCur = eventTitleArtifact(cur.title)
  const artE = eventTitleArtifact(e.title)
  if (artCur && artE && artCur === artE && artCur.length >= 3) {
    strong = true
    score += 75
  }

  const kCur = registryKeyOf(curFlat, curRaw)
  const kE = registryKeyOf(eFlat, eRaw)
  if (kCur && kE && kCur === kE) {
    strong = true
    score += 85
  }

  const shaCur = String(curFlat.sha256 || '').trim().toLowerCase()
  const shaE = String(eFlat.sha256 || '').trim().toLowerCase()
  if (shaCur.length >= 16 && shaCur === shaE) {
    strong = true
    score += 90
  }

  // 无强关联时不计入（避免「同模块 + 时间近」凑满 8 条）
  if (!strong) return -1

  const t0 = eventTimeMs(cur)
  const t = eventTimeMs(e)
  if (Number.isFinite(t0) && Number.isFinite(t)) {
    const dt = Math.abs(t - t0)
    if (dt > windowMs) return -1
    score += Math.max(0, 15 - Math.floor(dt / (10 * 60 * 1000)))
  } else {
    return -1
  }

  return score
}

/** 同主机、时间窗内、与当前告警有实质关联的其它威胁事件 */
function listPreviewRelatedEvents(cur, events, windowMs = 2 * 60 * 60 * 1000) {
  if (!cur?.agent_id) return []
  return (events || [])
    .map((e) => ({ e, score: relatedEventScore(cur, e, windowMs) }))
    .filter((x) => x.score >= RELATED_EVENT_MIN_SCORE)
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score
      const tb = eventTimeMs(b.e)
      const ta = eventTimeMs(a.e)
      if (Number.isFinite(tb) && Number.isFinite(ta)) return tb - ta
      return String(b.e.id).localeCompare(String(a.e.id))
    })
    .slice(0, RELATED_EVENT_MAX)
    .map((x) => x.e)
}

function collectFileRowsFromEvent(e, seen) {
  const raw = parseEventEvidence(e)
  const flat = evidenceFlatOf(raw)
  const rows = []
  const push = (name, path, extra = '') => {
    const p = String(path || '').trim()
    if (!p) return
    const key = p.toLowerCase()
    if (seen.has(key)) return
    const fileLike = /\.(exe|dll|sys|ps1|bat|cmd|vbs|js|msi|scr|ini|lnk|jar|hta)$/i.test(p)
      || /\\Users\\Public\\|\\Temp\\|\\AppData\\/i.test(p)
      || !!flat.sha256
    if (!fileLike && !/^(file|process|fim|driver|startup)$/i.test(String(e?.module || ''))) return
    seen.add(key)
    rows.push({
      name: name || baseName(p) || p,
      path: p,
      extra,
      sourceTitle: e?.title || '关联告警',
      eventId: e?.id,
    })
  }
  const path = flat.path || flat.image || flat.TargetFilename || evidencePathOf(flat, raw) || ''
  const name = evidenceNameOf(flat, path)
  if (path) {
    const extra = flat.sha256 ? `SHA256 ${String(flat.sha256).slice(0, 16)}…` : ''
    push(name, path, extra)
  }
  if (flat.command_line) {
    const m = String(flat.command_line).match(/"([^"]+\.(?:exe|dll|ps1|bat|cmd))"/i)
      || String(flat.command_line).match(/(\S+\.(?:exe|dll|ps1|bat|cmd))/i)
    if (m) push(baseName(m[1]), m[1])
  }
  return rows
}

/** 入侵防护 · 恶意文件：可提取样本路径或典型文件类威胁（含多数「规则命中」落地告警） */
function isMalwareFileEvent(e) {
  if (!e) return false
  const seen = new Set()
  if (collectFileRowsFromEvent(e, seen).length) return true
  const mod = String(e.module || '').toLowerCase()
  if (['file', 'image', 'memory', 'kernel'].includes(mod)) return true
  const t = String(e.title || '')
  if (/FIM|文件新增|文件修改|文件删除|恶意文件|样本|隔离|木马|病毒|投放|落地|可执行|未签名.*dll|driver_load/i.test(t)) return true
  if (/Public|目录投放|Drop|Softcnapp|PUA|PUP/i.test(t)) return true
  const art = eventTitleArtifact(t)
  if (art && (/\.(exe|dll|sys|bat|cmd|ps1|vbs|msi|scr|hta|jar|lnk)$/i.test(art) || (art.length >= 2 && /规则命中/.test(t)))) return true
  const raw = parseEventEvidence(e)
  const flat = evidenceFlatOf(raw)
  if (flat.sha256 || flat.signer === 'NotSigned') {
    const p = evidencePathOf(flat, raw)
    if (p && /\.(exe|dll|sys|bat|cmd|ps1)/i.test(p)) return true
  }
  if (catOf(e) === 'file') return true
  return false
}

function eventFileHint(e) {
  const seen = new Set()
  const rows = collectFileRowsFromEvent(e, seen)
  if (rows.length) return rows[0].path
  const raw = parseEventEvidence(e)
  const flat = evidenceFlatOf(raw)
  return evidencePathOf(flat, raw) || eventTitleArtifact(e?.title) || '—'
}

const eventEvidence = computed(() => parseEventEvidence(activeEvent.value))
const threatEvidenceEnrich = ref({})
const threatProcessSnap = ref([])
const evidenceFlat = computed(() => enrichEvidenceFlat(
  evidenceFlatOf(eventEvidence.value),
  eventEvidence.value,
  activeEvent.value,
  threatEvidenceEnrich.value,
  threatTree.value,
))
const evidenceDesc = computed(() => describeEvidence(evidenceFlat.value))
const isRegistryEvidence = computed(() => {
  const ev = evidenceFlat.value || {}
  const et = String(ev.etype || eventEvidence.value.etype || '')
  return !!(ev.key || ev.reg_key || ev.value_name || /^registry_|^persist_/.test(et))
})
const evidencePath = computed(() => evidencePathOf(evidenceFlat.value, eventEvidence.value))
const evidenceName = computed(() => evidenceNameOf(evidenceFlat.value, evidencePath.value))
const threatHostAgent = computed(() => {
  const id = activeEvent.value?.agent_id
  if (!id) return null
  return agents.value.find((a) => a.agent_id === id) || null
})
const evidenceChainRows = computed(() => {
  const flat = evidenceFlat.value || {}
  const root = eventEvidence.value || {}
  const chain = Array.isArray(flat.chain) ? flat.chain : (Array.isArray(root.chain) ? root.chain : [])
  return chain.map((c) => ({
    ts: c.ts || c.time || '',
    etype: c.etype || '',
    summary: c.summary || c.reg_key || c.path || '',
    command_line: c.command_line || c.command || c.script_block || '',
  }))
})
const evidenceCommandLine = computed(() => resolveCommandLine(evidenceFlat.value, eventEvidence.value))
const listEvidenceCommandLine = computed(() => resolveCommandLine(listEvidenceFlat.value, listEventEvidence.value))

const listFocusId = ref(null)
const listFocusEvent = ref(null)
const edMore = ref(false)
const edAlertTab = ref('behavior')
const edFold = ref({ overview: false, host: false, attck: false, alert: false, judge: false })
const listEventEvidence = computed(() => parseEventEvidence(listFocusEvent.value))
const listEvidenceFlat = computed(() => enrichEvidenceFlat(
  evidenceFlatOf(listEventEvidence.value),
  listEventEvidence.value,
  listFocusEvent.value,
  {},
  null,
))
const listEvidenceDesc = computed(() => describeEvidence(listEvidenceFlat.value))
const listEvidencePath = computed(() => evidencePathOf(listEvidenceFlat.value, listEventEvidence.value))
const listEvidenceName = computed(() => evidenceNameOf(listEvidenceFlat.value, listEvidencePath.value))
const listFocusAgent = computed(() => {
  const id = listFocusEvent.value?.agent_id
  if (!id) return null
  return agents.value.find((a) => a.agent_id === id) || null
})
const listFocusAgentMeta = computed(() => {
  const a = listFocusAgent.value
  if (!a) return {}
  let m = a.meta
  if (!m && a.meta_json) {
    try { m = JSON.parse(a.meta_json) } catch { m = {} }
  }
  return (m && typeof m === 'object') ? m : {}
})
const listFocusGroupLabel = computed(() => {
  const id = listFocusEvent.value?.agent_id
  if (!id) return '—'
  const hit = (groupItems.value || []).find((g) => {
    const ids = Array.isArray(g.agent_ids) ? g.agent_ids : String(g.agent_ids_json || g.agent_ids || '')
    if (Array.isArray(ids)) return ids.includes(id)
    return String(ids).includes(id)
  })
  return hit?.name || listFocusAgentMeta.value.group || listFocusAgentMeta.value.workplace || '未分组'
})
const listFocusUserRaw = computed(() => {
  const ev = listEvidenceFlat.value || {}
  const meta = listFocusAgentMeta.value || {}
  const a = listFocusAgent.value || {}
  return String(
    ev.user || ev.username || ev.account || ev.User || ev.owner
    || a.username || a.user || a.last_user
    || meta.last_user || meta.user || meta.logged_on_user || meta.username || ''
  ).trim()
})
const listFocusUser = computed(() => {
  const raw = listFocusUserRaw.value
  if (raw) {
    const parts = raw.replace(/\//g, '\\').split('\\')
    return parts[parts.length - 1] || raw
  }
  const p = String(listEvidencePath.value || listEvidenceFlat.value.command_line || '')
  const m = p.match(/\\Users\\([^\\]+)\\/i) || p.match(/\\Documents and Settings\\([^\\]+)\\/i)
  return m ? m[1] : ''
})
const listFocusUserDomain = computed(() => {
  const raw = listFocusUserRaw.value
  if (!raw) return ''
  const s = raw.replace(/\//g, '\\')
  if (s.includes('\\')) return s
  return ''
})
const listFocusOsLabel = computed(() => {
  const a = listFocusAgent.value
  const meta = listFocusAgentMeta.value || {}
  const base = a?.os_family || meta.os || meta.caption || meta.os_name || '—'
  const ver = a?.version ? ` · Agent v${a.version}` : ''
  return `${base}${ver}`
})
const listFocusMac = computed(() => {
  const meta = listFocusAgentMeta.value || {}
  const a = listFocusAgent.value || {}
  return String(
    meta.mac || meta.mac_address || meta.MacAddress || a.mac || a.mac_address || ''
  ).trim()
})
const listFocusAttck = computed(() => {
  const e = listFocusEvent.value
  if (!e) return { technique: '', label: '', tactic: '', tacticLabel: '' }
  return guessAttck(e.title, e.module)
})
const listAttckRing = computed(() => {
  const hit = listFocusAttck.value?.tactic || ''
  return Object.entries(TACTIC_CN).map(([key, label]) => ({
    key, label, hit: !!hit && key === hit,
  }))
})
function looksBadName(s) {
  const t = String(s || '').trim()
  if (!t) return true
  // 残缺片段：如 \SU84O、无扩展名的短乱码
  if (/^\\?[A-Za-z0-9_-]{1,10}$/.test(t) && !/\.(exe|dll|sys|bat|ps1|cmd)$/i.test(t)) return true
  return false
}
const listRootCause = computed(() => {
  const ev = listEvidenceFlat.value || {}
  const path = listEvidencePath.value || ev.path || ev.image || ev.TargetFilename || ''
  let name = ev.process_name || ev.name || ev.module_name || ev.task_name || ''
  if (looksBadName(name) && path) name = baseName(path) || name
  if (looksBadName(name) && listEvidenceName.value && !looksBadName(listEvidenceName.value)) {
    name = listEvidenceName.value
  }
  if (looksBadName(name) && ev.command_line) name = baseName(String(ev.command_line).split(/\s+/)[0]) || name
  const pid = ev.pid != null && ev.pid !== '' ? ` (PID: ${ev.pid})` : ''
  if (name && !looksBadName(name)) return `${name}${pid}`
  if (ev.key || ev.reg_key) {
    return `${ev.value_name || '注册表项'} · ${ev.key || ev.reg_key}`
  }
  if (path) return `${baseName(path) || path}${pid}`
  const title = String(listFocusEvent.value?.title || '')
  const m = title.match(/[·:：]\s*([^\s·]+)$/)
  if (m && !looksBadName(m[1])) return `${m[1]}${pid}`
  return title || '—'
})
const listOverviewCore = computed(() => {
  const e = listFocusEvent.value
  if (!e) return []
  const ev = listEvidenceFlat.value || {}
  const root = listEventEvidence.value || {}
  const et = String(ev.etype || root.etype || listInferredEtype.value || '')
  const isNet = /^network_|^dns_/.test(et) || !!(ev.remote || ev.remote_ip || ev.domain)
  const procPath = ev.payload_path || ev.task_execute || ev.path || ev.image || ev.process_path || (!isNet ? listEvidencePath.value : '') || ''
  const add = (k, v, opt = {}) => {
    const s = v == null || v === '' ? (opt.keepEmpty ? '—' : '') : String(v)
    if (!s && !opt.keepEmpty) return null
    return { k, v: s || '—', mono: !!opt.mono, root: !!opt.root }
  }
  const rows = [
    add('事件根因', listRootCause.value, { root: true, keepEmpty: true }),
    add('事件类型', et, { keepEmpty: true }),
    add('检测模块', modLabel(e.module) || e.module, { keepEmpty: true }),
    add('进程名', ev.process_name || ev.name || (!isNet ? listEvidenceName.value : '')),
    add('PID', ev.pid),
    add('进程命令行', listEvidenceCommandLine.value || ev.command_line || ev.command, { mono: true, keepEmpty: true }),
    add('进程 / 文件路径', procPath, { mono: true }),
    add('父进程', ev.parent_name ? `${ev.parent_name}${ev.ppid != null ? `（PPID ${ev.ppid}）` : ''}` : (ev.ppid != null ? `PPID ${ev.ppid}` : '')),
    add('用户', listFocusUser.value || ev.user),
    add('远程地址', ev.remote || ev.remote_ip, { mono: true }),
    add('域名', ev.domain || ev.query, { mono: true }),
    add('本地地址', isNet ? ev.local : '', { mono: true }),
    add('协议', ev.proto || ev.protocol),
    add('文件 SHA256', ev.sha256, { mono: true }),
    add('文件签名', ev.signer || (ev.signed != null && ev.signed !== '' ? evValueText('signed', ev.signed) : '')),
    add('注册表键', ev.key || ev.reg_key, { mono: true }),
    add('值名', ev.value_name),
    add('写入值', ev.value != null && ev.value !== '' ? ev.value : '', { mono: true }),
    add('规则 ID', root.rule_id || ev.watch || ev.rule_id, { mono: true }),
    add('任务载荷', ev.task_execute || ev.payload_path, { mono: true }),
    add('任务工作目录', ev.task_workdir, { mono: true }),
    add('任务定义', ev.task_def_path, { mono: true }),
    add('匹配特征', root.matched || ev.matched || ev.task_execute || ev.payload_path, { mono: true }),
    add('告警日志数', eventLogCount(e), { keepEmpty: true }),
    add('首次发现', fmtTime(e.created_at), { keepEmpty: true }),
    add('最近活跃', fmtTime(e.updated_at || e.created_at), { keepEmpty: true }),
  ].filter(Boolean)
  const seen = new Set()
  return rows.filter((r) => {
    if (seen.has(r.k)) return false
    seen.add(r.k)
    return true
  })
})
const listOverviewExtra = computed(() => {
  const ev = listEvidenceFlat.value || {}
  const used = new Set(listOverviewCore.value.map((r) => r.k))
  const descRows = listEvidenceDesc.value?.rows || []
  const out = []
  const push = (k, v, mono) => {
    if (v == null || v === '' || used.has(k)) return
    used.add(k)
    out.push({ k, v: String(v), mono: !!mono })
  }
  for (const r of descRows) push(r.k, r.v, r.mono)
  const skip = new Set([
    'command_line', 'command', 'path', 'image', 'TargetFilename', 'name', 'process_name',
    'pid', 'ppid', 'parent_name', 'user', 'sha256', 'signer', 'signed', 'key', 'reg_key',
    'value_name', 'value', 'remote', 'remote_ip', 'domain', 'query', 'etype', 'watch',
    'matched', 'rule_id', 'module_name', 'task_name',
  ])
  for (const [k, v] of Object.entries(ev)) {
    if (skip.has(k) || v == null || v === '' || typeof v === 'object') continue
    push(colLabel(k) || k, evValueText(k, v), /path|hash|sha|cmd|key|guid/i.test(k))
  }
  return out.slice(0, 40)
})
const listBehaviorDetailRows = computed(() => {
  const core = listOverviewCore.value || []
  const extra = edMore.value ? (listOverviewExtra.value || []) : []
  return [...core, ...extra]
})
const listPreviewRelated = computed(() => {
  const cur = listFocusEvent.value
  if (!cur) return []
  return listPreviewRelatedEvents(cur, allEvents.value || [])
})

const listAlertBehaviors = computed(() => {
  const cur = listFocusEvent.value
  if (!cur) return []
  const ev = listEvidenceFlat.value || {}
  const rows = [{
    eventId: cur.id,
    severity: cur.severity,
    title: cur.title,
    sub: [listEventEvidence.value.matched, ev.etype, modLabel(cur.module)].filter(Boolean).join(' · ') || '当前告警',
    time: fmtTime(cur.updated_at || cur.created_at),
    isCurrent: true,
  }]
  for (const e of listPreviewRelated.value) {
    const raw = parseEventEvidence(e)
    const flat = evidenceFlatOf(raw)
    const p = evidencePathOf(flat, raw)
    rows.push({
      eventId: e.id,
      severity: e.severity,
      title: e.title,
      sub: [raw.matched || flat.matched, p ? baseName(p) : '', modLabel(e.module)].filter(Boolean).join(' · ')
        || `${e.hostname || short(e.agent_id)} · ${modLabel(e.module) || '—'}`,
      time: fmtTime(e.updated_at || e.created_at),
      isCurrent: false,
    })
  }
  return rows
})

const listMaliciousFiles = computed(() => {
  const cur = listFocusEvent.value
  if (!cur) return []
  const seen = new Set()
  const out = []
  for (const row of collectFileRowsFromEvent(cur, seen)) out.push(row)
  // 仅合并强关联告警中的文件，避免同主机无关样本凑数
  for (const e of listPreviewRelated.value) {
    for (const row of collectFileRowsFromEvent(e, seen)) out.push(row)
    if (out.length >= 10) break
  }
  return out.slice(0, 10)
})
const listInferredEtype = computed(() => {
  const ev = listEvidenceFlat.value || {}
  if (ev.etype) return ev.etype
  const t = String(listFocusEvent.value?.title || '')
  if (/FIM新增|FIM 新增/.test(t)) return 'fim_add'
  if (/FIM修改/.test(t)) return 'fim_modify'
  if (/FIM删除/.test(t)) return 'fim_delete'
  if (/外联/.test(t)) return 'network_connect'
  if (/注册表/.test(t)) return 'registry_set'
  if (/进程|父链|规则命中/.test(t)) return 'process_create'
  return ''
})
const listFocusIndex = computed(() => {
  const id = listFocusId.value
  if (id == null) return -1
  return filteredEvents.value.findIndex((e) => e.id === id)
})
const listFocusHasPrev = computed(() => listFocusIndex.value > 0)
const listFocusHasNext = computed(() => {
  const i = listFocusIndex.value
  return i >= 0 && i < filteredEvents.value.length - 1
})

function clearListFocus() {
  listFocusId.value = null
  listFocusEvent.value = null
  edMore.value = false
  edAlertTab.value = 'behavior'
}
function scrollExpandIntoView() { /* 右侧面板模式不再行内滚动 */ }
async function selectListEvent(e) {
  if (!e?.id) return
  listFocusId.value = e.id
  listFocusEvent.value = e
  edMore.value = false
  edAlertTab.value = 'behavior'
  try {
    const r = await getEvent(e.id)
    if (listFocusId.value === e.id) listFocusEvent.value = r?.item || e
  } catch { /* 列表项已够用 */ }
}
async function navListFocus(delta) {
  const i = listFocusIndex.value
  if (i < 0) return
  const next = filteredEvents.value[i + delta]
  if (!next) return
  const pageSize = evtPageSize.value
  const targetPage = Math.floor((i + delta) / pageSize) + 1
  if (targetPage !== evtPage.value) evtPage.value = targetPage
  await selectListEvent(next)
}

function resolveParentInfo(ev, agentId, procItems) {
  const ppid = ev?.ppid
  let name = String(ev?.parent_name || '').trim()
  const snapItems = procItems
    || (selected.value?.agent_id === agentId ? (snap.value?.items || []) : [])
    || threatProcessSnap.value
    || []
  // 从已加载的本机进程快照 / 时间线补全父进程名
  if (!name && ppid != null && ppid !== '') {
    const pidStr = String(ppid)
    const hit = snapItems.find((r) => String(r.pid) === pidStr)
    if (hit?.name) name = String(hit.name)
    if (!name) {
      const tl = (timelineItems.value || []).find((t) => {
        const d = parseTlDetail(t) || {}
        return String(t.agent_id) === String(agentId) && String(d.pid) === pidStr && d.name
      })
      if (tl) name = String((parseTlDetail(tl) || {}).name || '')
    }
  }
  // matched 里可能只有 ppid=xxx
  let matchedPpid = ppid
  if (matchedPpid == null || matchedPpid === '') {
    const m = String(eventEvidence.value.matched || '').match(/ppid\s*=\s*(\d+)/i)
    if (m) matchedPpid = m[1]
  }
  return { name, ppid: matchedPpid ?? ppid }
}

// 威胁图：主机 → 父进程 → 命中对象（无父进程信息时退化为 主机 → 模块 → 命中对象）
const graphNodes = computed(() => {
  const e = activeEvent.value
  if (!e) return []
  const ev = eventEvidence.value.evidence || {}
  const nodes = [{
    key: 'host', kind: '主机', tone: 'host',
    title: e.hostname || short(e.agent_id), sub: agentIp(e.agent_id), meta: [],
  }]
  const desc = evidenceDesc.value
  if (desc) {
    if (desc.actor) {
      nodes.push({
        key: 'actor', kind: '发起进程', tone: 'proc', edge: '运行',
        title: desc.actor.name || `PID ${desc.actor.pid}`,
        sub: desc.actor.path && desc.actor.path !== desc.actor.name ? shortPath(desc.actor.path) : (desc.actor.pid !== '' ? `PID ${desc.actor.pid}` : ''),
        meta: desc.actor.path && desc.actor.pid !== '' ? [{ k: 'PID', v: desc.actor.pid }] : [],
      })
    } else {
      nodes.push({ key: 'mod', kind: '检测模块', tone: 'mod', edge: '上报', title: modLabel(e.module) || '—', sub: '终端上报', meta: [] })
    }
    nodes.push({
      key: 'hit', kind: '威胁', tone: 'hit', edge: desc.edge || '规则命中',
      title: desc.title || '—', sub: desc.sub ? shortPath(desc.sub) : '', meta: desc.meta || [],
    })
    return nodes
  }
  const parent = resolveParentInfo(ev, e.agent_id)
  if (parent.name || parent.ppid) {
    const orphan = !parent.name
    nodes.push({
      key: 'parent', kind: '父进程', tone: orphan ? 'miss' : 'proc', edge: orphan ? '断链' : '运行',
      title: parent.name || '未知进程（已退出/不可见）',
      sub: parent.ppid != null && parent.ppid !== '' ? `PPID ${parent.ppid}` : '',
      meta: orphan ? [{ k: '说明', v: '父链缺失，常见于注入或父进程已退出' }] : [],
    })
  } else {
    nodes.push({
      key: 'mod', kind: '检测模块', tone: 'mod', edge: '上报',
      title: modLabel(e.module) || '—', sub: '终端上报', meta: [],
    })
  }
  const meta = []
  if (ev.process_guid) meta.push({ k: 'GUID', v: ev.process_guid })
  if (ev.pid != null && ev.pid !== '') meta.push({ k: 'PID', v: ev.pid })
  if (ev.elevated != null && ev.elevated !== '') meta.push({ k: '提权', v: String(ev.elevated) })
  if (ev.integrity) meta.push({ k: '完整性', v: ev.integrity })
  if (ev.user) meta.push({ k: '用户', v: String(ev.user).split('\\').pop() })
  if (ev.signed) meta.push({ k: '签名', v: ev.signed, cls: String(ev.signed) === 'Valid' ? 'ok' : 'warn' })
  if (ev.uptime) meta.push({ k: '运行', v: ev.uptime })
  if (isRegistryEvidence.value) {
    if (ev.hive) meta.push({ k: 'Hive', v: ev.hive })
    if (ev.change) meta.push({ k: '变更', v: evValueText('change', ev.change) })
    if (ev.value != null && ev.value !== '') meta.push({ k: '值', v: String(ev.value).slice(0, 48) })
  }
  const hitTitle = isRegistryEvidence.value
    ? (ev.value_name || ev.label || evidenceName.value || '注册表项')
    : (evidenceName.value || '命中对象')
  const hitSub = isRegistryEvidence.value
    ? shortPath(ev.key || ev.reg_key || eventEvidence.value.matched || '—')
    : shortPath(evidencePath.value || eventEvidence.value.matched || '—')
  nodes.push({
    key: 'hit', kind: '威胁', tone: 'hit', edge: parent.name || parent.ppid ? '创建' : (isRegistryEvidence.value ? '注册表变更' : '规则命中'),
    title: hitTitle,
    sub: hitSub,
    meta,
  })
  return nodes
})

const EV_ENUM = {
  change: { add: '新增', modify: '修改', delete: '删除' },
  category: { persistence: '持久化', defense_evasion: '防御绕过', credential_access: '凭据访问', privilege_escalation: '权限提升' },
  elevated: { true: '是', false: '否' },
  signed: { Valid: '有效签名', NotSigned: '未签名', HashMismatch: '签名不匹配', UnknownError: '未知' },
}
function evValueText(k, raw) {
  if (raw == null) return ''
  if (Array.isArray(raw)) return raw.map((x) => (typeof x === 'object' ? JSON.stringify(x) : String(x))).join(', ')
  if (typeof raw === 'object') return JSON.stringify(raw)
  const s = String(raw)
  if (k === 'logon_type' && LOGON_TYPE_CN[s]) return `${LOGON_TYPE_CN[s]}（${s}）`
  const m = EV_ENUM[k]
  return m && m[s] ? `${m[s]}（${s}）` : s
}
// 同名字段在不同事件里含义不同：status 在 DNS 是解析结果码，在登录事件是 NTSTATUS
const EV_KEY_WHEN = {
  status: (group, et) => (group === 'DNS' ? /^dns_/.test(et) : group === '账号与登录' ? /^win_/.test(et) : group === '采集来源'),
  ip: (group, et) => group === '账号与登录' && /^win_/.test(et),
  process: (group, et) => group === '账号与登录' && /^win_/.test(et),
  name: (group, et) => (group === '对象' ? !!et && !/^process_/.test(et) : true),
}
// 证据详情：按语义分组，长文本（路径/命令行/哈希）独占整行并可复制
const EV_GROUPS = [
  { title: '对象', tone: 'cmd', keys: ['name'], when: (et) => !!et && !/^process_/.test(et) },
  { title: '注册表', tone: 'cmd', keys: ['hive', 'reg_key', 'key', 'value_name', 'value', 'old_value', 'value_type', 'change', 'label', 'category', 'watch', 'user_sid'] },
  { title: '进程', tone: 'proc', keys: ['name', 'pid', 'ppid', 'process_guid', 'parent_guid', 'parent_name', 'parent_path', 'user', 'session_id', 'create_time', 'elevated', 'integrity', 'uptime', 'uptime_sec', 'memory_mb', 'handles', 'process_name'] },
  { title: '命令与路径', tone: 'cmd', keys: ['command_line', 'command', 'path', 'directory', 'location', 'execute', 'arguments', 'working_directory', 'task_name', 'display_name', 'image', 'script_block', 'payload'] },
  { title: '文件与签名', tone: 'sig', keys: ['signed', 'signer', 'company', 'file_version', 'sha256', 'ext', 'size', 'size_kb', 'modified', 'created'] },
  { title: '网络', tone: 'net', keys: ['local', 'remote', 'proto', 'state', 'daddr', 'dport', 'saddr', 'sport'] },
  { title: 'DNS', tone: 'net', keys: ['query', 'domain', 'qtype_name', 'status_name', 'answers', 'cnames', 'dga_score', 'nx_count', 'window_sec', 'samples'] },
  { title: '目标进程', tone: 'proc', keys: ['target_path', 'target_pid', 'access', 'start_address', 'call_trace'] },
  { title: '账号与登录', tone: 'proc', keys: ['member', 'group', 'by', 'logon_type', 'ip', 'status', 'substatus', 'target', 'privileges', 'process'] },
  { title: '计划任务', tone: 'cmd', keys: ['task', 'content'] },
  { title: '威胁情报', tone: 'sig', keys: ['ioc_value', 'ioc_type', 'malware', 'intel_source', 'matched_from', 'trigger'] },
  { title: '采集来源', tone: 'other', keys: ['etype', 'source', 'event_id', 'channel', 'script_block_id', 'remote_ip', 'remote_port', 'old_sha256', 'old_size', 'qtype', 'lib', 'ioc_id'] },
]
const EV_WIDE = new Set(['command_line', 'command', 'path', 'parent_path', 'sha256', 'signer', 'arguments', 'working_directory', 'execute', 'directory', 'image', 'key', 'reg_key', 'value', 'old_value', 'matched'])
const EV_SIDE_SKIP = new Set([
  'name', 'path', 'command', 'command_line', 'pid', 'ppid', 'parent_name', 'user', 'signed', 'signer',
  'company', 'sha256', 'uptime', 'ext', 'size', 'size_kb',
  'key', 'reg_key', 'value_name', 'value', 'old_value', 'hive', 'label', 'etype',
])
const TACTIC_CN = {
  initial_access: '初始访问', execution: '执行', persistence: '持久化', privilege_escalation: '权限提升',
  defense_evasion: '防御绕过', credential_access: '凭据访问', discovery: '发现', lateral_movement: '横向移动',
  collection: '收集', command_and_control: '命令与控制', exfiltration: '数据渗出', impact: '影响',
}
/** 检出行为「威胁阶段分布」展示名 + 图标（对齐参考图） */
const TACTIC_STAGE = [
  { key: 'initial_access', stageLabel: '权限获取', icon: 'key', color: '#f5c542' },
  { key: 'execution', stageLabel: '后门执行', icon: 'door', color: '#f0a83a' },
  { key: 'persistence', stageLabel: '权限维持', icon: 'pin', color: '#ef8f28' },
  { key: 'privilege_escalation', stageLabel: '权限提升', icon: 'up', color: '#e87a1c' },
  { key: 'defense_evasion', stageLabel: '防御绕过', icon: 'shield', color: '#e35f22' },
  { key: 'credential_access', stageLabel: '凭据窃取', icon: 'mask', color: '#dc4a2a' },
  { key: 'discovery', stageLabel: '信息收集', icon: 'search', color: '#d4382f' },
  { key: 'lateral_movement', stageLabel: '横向移动', icon: 'move', color: '#c92a3a' },
  { key: 'collection', stageLabel: '数据收集', icon: 'db', color: '#b91c3c' },
  { key: 'command_and_control', stageLabel: '命令控制', icon: 'radio', color: '#9f1239' },
  { key: 'exfiltration', stageLabel: '数据泄露', icon: 'leak', color: '#94a3b8' },
  { key: 'impact', stageLabel: '攻击破坏', icon: 'target', color: '#64748b' },
]
/** 24×24 单色图标 path（节点内白描） */
const STAGE_ICON_PATH = {
  key: 'M12 2a5 5 0 0 0-5 5v2H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1V7a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v2H9V7a3 3 0 0 1 3-3zm0 9.2a1.6 1.6 0 0 1 .8 3v1.3h-1.6V16.2a1.6 1.6 0 0 1 .8-3z',
  door: 'M5 3h10a2 2 0 0 1 2 2v14H5V5a2 2 0 0 1 2-2zm2 2v12h8V5H7zm8.5 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2zM4 21h16v2H4v-2z',
  pin: 'M12 2a5 5 0 0 0-5 5v2H5.5A1.5 1.5 0 0 0 4 10.5v9A1.5 1.5 0 0 0 5.5 21h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 18.5 9H17V7a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v2H9V7a3 3 0 0 1 3-3zm-4.2 9.3 1.4-1.4 2.8 2.8 4.6-4.6 1.4 1.4-6 6-4.2-4.2z',
  up: 'M12 2a5 5 0 0 0-5 5v2H5.5A1.5 1.5 0 0 0 4 10.5v9A1.5 1.5 0 0 0 5.5 21h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 18.5 9H17V7a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v2H9V7a3 3 0 0 1 3-3zm0 7 3.2 3.2-1.4 1.4L13 13.8V19h-2v-5.2l-.8.8-1.4-1.4L12 11z',
  shield: 'M12 2 4 5v6.5c0 5.1 3.4 9.8 8 11 4.6-1.2 8-5.9 8-11V5l-8-3zm0 2.2 6 2.2v5.1c0 4-2.6 7.8-6 8.9-3.4-1.1-6-4.9-6-8.9V6.4l6-2.2zm-3.2 6.1 2 2.1L15.5 8l1.4 1.4-5.1 5.3-3.4-3.6 1.4-1.4z',
  mask: 'M12 3c-2.4 0-4.5 1.3-5.7 3.2C4.8 7.6 4 9.6 4 12c0 2.8 1.3 5.2 3.3 6.7L6 21h3l1.2-1.5c.6.1 1.2.2 1.8.2s1.2-.1 1.8-.2L15 21h3l-1.3-2.3C18.7 17.2 20 14.8 20 12c0-2.4-.8-4.4-2.3-5.8C16.5 4.3 14.4 3 12 3zm0 2c1.7 0 3.2.9 4.1 2.3.3.5.6 1 .8 1.7H7.1c.2-.7.5-1.2.8-1.7C8.8 5.9 10.3 5 12 5zM8.5 12.2a1.3 1.3 0 1 1 0 2.6 1.3 1.3 0 0 1 0-2.6zm7 0a1.3 1.3 0 1 1 0 2.6 1.3 1.3 0 0 1 0-2.6zM9.2 16.2h5.6c-.5.6-1.5 1-2.8 1s-2.3-.4-2.8-1z',
  search: 'M9 3h7a2 2 0 0 1 2 2v8.2l-1.8-1.8V5H9v12h4.2l1.6 1.6.4.4H9a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zm1.5 3h4v1.5h-4V6zm0 3h4v1.5h-4V9zm7.2 2.5a3.3 3.3 0 1 1-1.3 6.3l-2 2-1.3-1.3 2-2a3.3 3.3 0 0 1 2.6-5zm0 1.7a1.6 1.6 0 1 0 0 3.2 1.6 1.6 0 0 0 0-3.2z',
  move: 'M7.5 7.5 4 11l3.5 3.5 1.4-1.4L7.8 12H11v5.2l-1.1-1.1-1.4 1.4L12 21l3.5-3.5-1.4-1.4-1.1 1.1V12h3.2l-1.1 1.1 1.4 1.4L20 11l-3.5-3.5-1.4 1.4 1.1 1.1H13V5.8l1.1 1.1 1.4-1.4L12 3 8.5 6.5l1.4 1.4L11 5.8V10H7.8l1.1-1.1-1.4-1.4z',
  db: 'M12 2c-4.4 0-8 1.6-8 3.5v13C4 20.4 7.6 22 12 22s8-1.6 8-3.5v-13C20 3.6 16.4 2 12 2zm0 2c3.3 0 6 .9 6 1.5S15.3 7 12 7 6 6.1 6 5.5 8.7 4 12 4zm6 4.2v2.3c0 .6-2.7 1.5-6 1.5s-6-.9-6-1.5V8.2c1.5.8 3.7 1.3 6 1.3s4.5-.5 6-1.3zm0 5v2.3c0 .6-2.7 1.5-6 1.5s-6-.9-6-1.5v-2.3c1.5.8 3.7 1.3 6 1.3s4.5-.5 6-1.3z',
  radio: 'M12 2a1 1 0 0 1 1 1v2.1a7 7 0 0 1 5 6.7h-2a5 5 0 0 0-4-4.9V14a3 3 0 1 1-2 0V6.9a5 5 0 0 0-4 4.9H4a7 7 0 0 1 5-6.7V3a1 1 0 0 1 1-1zm0 14.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zM4.7 16.3l1.4 1.4A6.9 6.9 0 0 1 5 14h2c0 1 .3 2 .8 2.8l-1.5 1.5a8.8 8.8 0 0 1-1.6-2zm14.6 0a8.8 8.8 0 0 1-1.6 2l-1.5-1.5c.5-.8.8-1.8.8-2.8h2c0 .9-.3 1.7-.7 2.3z',
  leak: 'M12 2c-4.4 0-8 1.6-8 3.5v4.2c1.5.8 3.7 1.3 6 1.3.7 0 1.4 0 2-.1V13h2V9.7c2.2-.3 4.1-1 6-1.8V5.5C20 3.6 16.4 2 12 2zm0 2c3.3 0 6 .9 6 1.5S15.3 7 12 7 6 6.1 6 5.5 8.7 4 12 4zm1 9v3.2l1.5-1.5 1.4 1.4L12 21l-3.9-3.9 1.4-1.4L11 16.2V13h2zM4 12.8v3.7C4 18.4 7.6 20 12 20c.3 0 .7 0 1-.1v-2c-.3 0-.7.1-1 .1-3.3 0-6-.9-6-1.5v-2.2c-.7-.3-1.4-.7-2-1.1z',
  target: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 2a8 8 0 0 1 8 8h-2a6 6 0 0 0-6-6V4zm0 4a4 4 0 0 1 4 4h-2a2 2 0 0 0-2-2V8zm0 3a1 1 0 1 1 0 2 1 1 0 0 1 0-2zm-8 1a8 8 0 0 1 8-8v2a6 6 0 0 0-6 6H4zm8 8a8 8 0 0 1-8-8h2a6 6 0 0 0 6 6v2zm8-8a8 8 0 0 1-8 8v-2a6 6 0 0 0 6-6h2z',
}
function guessAttck(title, module) {
  const t = String(title || '')
  const tl = t.toLowerCase()
  const m = String(module || '').toLowerCase()
  const hit = (technique, label, tactic) => ({
    technique, label, tactic, tacticLabel: TACTIC_CN[tactic] || tactic,
  })
  if (/日志被清空/.test(t)) return hit('T1070.001', '清除 Windows 事件日志', 'defense_evasion')
  if (/账号创建/.test(t)) return hit('T1136.001', '创建本地账号', 'persistence')
  if (/加入.*组/.test(t)) return hit('T1098', '账号操纵', 'persistence')
  if (/登录失败/.test(t)) return hit('T1110', '暴力破解', 'credential_access')
  if (/显式凭据/.test(t)) return hit('T1078', '有效账号', 'defense_evasion')
  if (/lsass/i.test(tl)) return hit('T1003.001', 'LSASS 内存读取', 'credential_access')
  if (/疑似dga|nxdomain/i.test(tl)) return hit('T1568.002', '域名生成算法(DGA)', 'command_and_control')
  if (/情报\s*ioc|IOC\s*命中/i.test(t) || m === 'ioc') return hit('T1071', '应用层协议通信', 'command_and_control')
  if (/powershell\s*脚本块/i.test(tl)) return hit('T1059.001', 'PowerShell', 'execution')
  if (/服务安装|服务创建/.test(t)) return hit('T1543.003', 'Windows 服务', 'persistence')
  if (/计划任务/.test(t) || m === 'task') return hit('T1053.005', '计划任务', 'persistence')
  if (/组策略|scripts\.ini|startup/i.test(tl) || /FIM新增|FIM修改|FIM删除/.test(t)) {
    if (/组策略|scripts\.ini/i.test(tl)) return hit('T1037.001', '登录脚本 / 组策略', 'persistence')
    return hit('T1105', '入口工具传输', 'command_and_control')
  }
  if (/Public\s*目录|目录投放|投放可执行|可执行文件/.test(t)) return hit('T1204.002', '恶意文件用户执行', 'execution')
  if (/父链缺失|临时目录进程|可疑路径进程/.test(t)) return hit('T1059', '命令与脚本解释器', 'execution')
  if (/dll|image_load|模块加载/i.test(tl) || m === 'image') return hit('T1574.002', 'DLL 侧加载', 'defense_evasion')
  if (/defender|排除项|exclusion/i.test(tl)) return hit('T1562.001', '削弱防御', 'defense_evasion')
  if (/持久化新增|持久化修改|winlogon|appinit/i.test(tl)) return hit('T1547.001', '注册表运行键 / 启动项', 'persistence')
  if (/注册表/.test(t) || m === 'registry') return hit('T1112', '修改注册表', 'defense_evasion')
  if (/注入|inject|remote.?thread/i.test(tl)) return hit('T1055', '进程注入', 'defense_evasion')
  if (/凭据|mimikatz/i.test(tl)) return hit('T1003.001', 'LSASS 内存', 'credential_access')
  if (/powershell|编码|script|cmd\.exe|wscript|mshta|脚本/i.test(tl)) return hit('T1059', '命令与脚本解释器', 'execution')
  if (/外联|c2|dns|网络|ioc|ip\s*命中/i.test(tl) || m === 'network' || m === 'dns') {
    return hit('T1071', '应用层协议', 'command_and_control')
  }
  if (/临时|落地|下载|文件创建|文件落地|fim_/i.test(tl) || m === 'file') {
    return hit('T1105', '入口工具传输', 'command_and_control')
  }
  if (m === 'startup') return hit('T1547.001', '注册表运行键', 'persistence')
  if (m === 'service') return hit('T1543.003', 'Windows 服务', 'persistence')
  if (m === 'process') return hit('T1059', '命令与脚本解释器', 'execution')
  if (/办公|office|宏|word|excel/i.test(tl)) return hit('T1204', '用户执行', 'execution')
  if (/规则命中/.test(t)) return hit('T1059', '命令与脚本解释器', 'execution')
  return { technique: '', label: '', tactic: '', tacticLabel: '' }
}
const eventAttck = computed(() => {
  const e = activeEvent.value
  if (!e) return { technique: '', label: '', tactic: '', tacticLabel: '' }
  const fromStory = (storyTech.value || [])[0]
  if (fromStory?.id) {
    return {
      technique: fromStory.id,
      label: fromStory.label || '',
      tactic: fromStory.tactic || '',
      tacticLabel: TACTIC_CN[fromStory.tactic] || fromStory.tactic || '',
    }
  }
  return guessAttck(e.title, e.module)
})
const evidenceGroups = computed(() => {
  const ev = eventEvidence.value.evidence || {}
  const used = new Set()
  const mk = (k) => {
    const raw = ev[k]
    const v = evValueText(k, raw)
    const it = { k, label: colLabel(k), v, wide: EV_WIDE.has(k), mono: EV_WIDE.has(k) || k === 'pid' || k === 'ppid', copy: EV_WIDE.has(k) }
    if (k === 'signed') it.badge = v === 'Valid' ? 'ok' : (v === 'NotSigned' || v === 'HashMismatch' ? 'bad' : 'warn')
    return it
  }
  const has = (k) => ev[k] != null && ev[k] !== ''
  const et = String(ev.etype || '')
  const groups = []
  const order = (items) => [...items.filter((x) => !x.wide), ...items.filter((x) => x.wide)]
  for (const g of EV_GROUPS) {
    if (g.when && !g.when(et)) continue
    const items = g.keys.filter((k) => has(k) && !used.has(k) && (!EV_KEY_WHEN[k] || EV_KEY_WHEN[k](g.title, et)))
      .map((k) => { used.add(k); return mk(k) })
    if (items.length) groups.push({ title: g.title, tone: g.tone, items: order(items) })
  }
  const rest = Object.keys(ev).filter((k) => !used.has(k) && has(k)).map(mk)
  if (rest.length) groups.push({ title: '其他证据字段', tone: 'other', items: order(rest) })
  return groups
})
const evidenceGroupsFull = computed(() => {
  const e = activeEvent.value
  if (!e) return []
  const mkMeta = (k, label, v, extra = {}) => {
    if (v == null || v === '') return null
    return { k, label, v: String(v), wide: !!extra.wide, mono: !!extra.mono, copy: !!extra.copy, badge: extra.badge }
  }
  const alertItems = [
    mkMeta('title', '告警标题', e.title, { wide: true }),
    mkMeta('severity', '严重级别', sevLabel(e.severity), { badge: e.severity === 'high' || e.severity === 'critical' ? 'bad' : 'warn' }),
    mkMeta('status', '处置状态', statusLabel(e.status)),
    mkMeta('rule_title', '规则名称', eventEvidence.value.rule_title || displayRuleTitle(e), { wide: true }),
    mkMeta('rule_id', '规则 ID', eventEvidence.value.rule_id, { mono: true, copy: true }),
    mkMeta('matched', '匹配特征', eventEvidence.value.matched, { wide: true, mono: true, copy: true }),
    mkMeta('rule_source', '规则来源', ruleSourceLabel.value),
    mkMeta('module', '检测模块', modLabel(e.module)),
    mkMeta('judge', '判定结果', judgeOf(e)),
  ].filter(Boolean)
  const hostItems = [
    mkMeta('hostname', '主机名', e.hostname || short(e.agent_id)),
    mkMeta('ip', 'IP', agentIp(e.agent_id), { mono: true }),
    mkMeta('agent_id', 'Agent ID', e.agent_id, { mono: true, copy: true, wide: true }),
    mkMeta('created_at', '首次发现', fmtTime(e.created_at)),
    mkMeta('updated_at', '最近活跃', fmtTime(e.updated_at)),
  ].filter(Boolean)
  const att = eventAttck.value
  const attckItems = [
    mkMeta('technique', '技术 ID', att.technique, { mono: true }),
    mkMeta('tech_label', '技术名称', att.label),
    mkMeta('tactic', '战术', att.tacticLabel || att.tactic),
  ].filter(Boolean)
  const out = [
    { title: '告警摘要', tone: 'cmd', items: alertItems },
    { title: '主机上下文', tone: 'proc', items: hostItems },
  ]
  if (attckItems.length) out.push({ title: 'ATT&CK 映射', tone: 'sig', items: attckItems })
  out.push(...evidenceGroups.value)
  if (!evidenceGroups.value.length && e.detail && !String(e.detail).startsWith('{')) {
    out.push({
      title: '文本详情',
      tone: 'other',
      items: [{ k: 'detail', label: '详情', v: String(e.detail), wide: true, mono: false, copy: true }],
    })
  }
  return out
})
const evidenceRawText = computed(() => {
  const e = activeEvent.value
  if (!e) return ''
  const payload = eventEvidence.value && Object.keys(eventEvidence.value).length
    ? eventEvidence.value
    : (e.detail || {})
  try {
    return typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2)
  } catch {
    return String(e.detail || '')
  }
})
const sideExtraFields = computed(() => {
  const ev = evidenceFlat.value || {}
  return Object.keys(ev)
    .filter((k) => !EV_SIDE_SKIP.has(k) && ev[k] != null && ev[k] !== '')
    .map((k) => {
      const raw = ev[k]
      return { k, label: colLabel(k), v: typeof raw === 'object' ? JSON.stringify(raw) : String(raw) }
    })
    .slice(0, 24)
})

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(String(text))
    okMsg.value = '已复制'
    setTimeout(() => { okMsg.value = '' }, 1500)
  } catch {
    error.value = '复制失败，请手动选择文本'
  }
}

const RULE_SOURCE_LABELS = {
  agent: 'Agent 快照规则',
  custom: '自定义快照规则',
  elastic: 'Elastic 导入（EVM/快照）',
  elastic_es: 'Elasticsearch EQL 引擎',
  evm: 'EVM 时间线规则',
  lolbin: 'LOLBin 内置规则',
  sensor: '内置传感器',
  platform: '主平台规则',
}

function inferRuleSource(e, ev) {
  const s = ev?.rule_source
  if (s && RULE_SOURCE_LABELS[s]) return s
  const t = String(e?.title || '')
  const mod = String(e?.module || '')
  if (mod === 'elastic_es' || t.startsWith('[ES/EQL]')) return 'elastic_es'
  if (t.startsWith('Elastic EVM：') || t.startsWith('EVM:')) return 'elastic'
  if (t.startsWith('规则命中：')) return 'agent'
  if (mod === 'timeline' && ev?.elastic_rule_id) return 'elastic'
  return s || 'agent'
}

function displayRuleTitle(e) {
  if (!e) return '—'
  const ev = parseEventEvidence(e)
  if (ev.rule_title) return ev.rule_title
  const t = String(e.title || '')
  if (t.startsWith('规则命中：')) {
    const rest = t.slice('规则命中：'.length).split(' · ')[0]
    return rest || t
  }
  if (t.startsWith('[ES/EQL]')) return t.slice('[ES/EQL]'.length).trim() || t
  if (t.startsWith('Elastic EVM：')) return t.slice('Elastic EVM：'.length).trim() || t
  if (t.startsWith('EVM:')) return t.slice(4).trim() || t
  return t || '—'
}

const ruleSourceLabel = computed(() => {
  const e = activeEvent.value
  const ev = eventEvidence.value
  const key = inferRuleSource(e, ev)
  return RULE_SOURCE_LABELS[key] || key || '系统'
})
const alertDesc = computed(() => {
  const e = activeEvent.value
  if (!e) return ''
  if (/规则命中/.test(e.title || '')) {
    return `终端「${modLabel(e.module)}」快照命中平台规则「${eventEvidence.value.rule_id || e.title}」，请结合右侧证据研判。`
  }
  if (String(e.detail || '').startsWith('{')) return e.title || ''
  return e.detail || e.title || ''
})

const MODULE_COLS = {
  process: ['name', 'pid', 'risk_tags', 'module_third_count', 'parent_name', 'user', 'signed', 'path', 'modules_summary'],
  service: ['name', 'display_name', 'risk_tags', 'status', 'start_type', 'account', 'signed', 'path'],
  task: ['task_name', 'risk_tags', 'status', 'command', 'author', 'last_run', 'triggers'],
  startup: ['name', 'location', 'command', 'path', 'user'],
  network: ['proto', 'local', 'remote', 'state', 'process_name', 'pid'],
  file: ['name', 'ext', 'signed', 'sha256', 'path', 'size_kb', 'modified'],
  user: ['name', 'source', 'enabled', 'last_logon', 'session', 'state'],
  sysinfo: ['caption', 'hostname', 'ip', 'domain', 'version', 'build'],
  driver: ['name', 'display_name', 'risk_tags', 'status', 'start_type', 'kind', 'signed', 'signer', 'path'],
  browser: ['browser', 'domain', 'title', 'url', 'visited_at', 'visit_count', 'profile'],
}

const columns = computed(() => {
  const items = snap.value?.items || []
  if (!items.length) return []
  const keys = Object.keys(items[0] || {})
  const prefer = MODULE_COLS[module.value] || ['name', 'task_name', 'display_name', 'status', 'path', 'command', 'command_line']
  const ordered = prefer.filter((k) => keys.includes(k))
  for (const k of keys) if (!ordered.includes(k)) ordered.push(k)
  return ordered.slice(0, 12)
})
function rowIsNoise(row) {
  if (!row) return false
  if (row.noise === true || row.noise === 1 || row.noise === 'true') return true
  const tags = String(row.risk_tags || '')
  return tags === '系统服务' || tags === '系统任务' || tags === '系统进程'
}
function rowIsRisk(row) {
  if (!row || rowIsNoise(row)) return false
  const score = Number(row.risk_score || 0)
  if (score >= 20) return true
  const tags = String(row.risk_tags || '')
  if (tags && !/^系统/.test(tags)) return true
  const path = String(row.path || row.command || row.command_line || row.execute || '')
  if (HOT_PATH_RE.test(path)) return true
  const signed = String(row.signed || '')
  if (signed && /not|unsigned|invalid|hash/i.test(signed) && !/valid/i.test(signed)) return true
  if (Number(row.module_third_count || 0) > 0) return true
  return false
}
const filteredSnapRows = computed(() => {
  let items = (snap.value?.items || []).slice(0, 800)
  if (snapView.value === 'risk') items = items.filter(rowIsRisk)
  else if (snapView.value === 'hide_noise') items = items.filter((r) => !rowIsNoise(r))
  const s = snapQ.value.trim().toLowerCase()
  if (!s) return items
  return items.filter((row) => {
    try {
      return JSON.stringify(row).toLowerCase().includes(s)
    } catch {
      return false
    }
  })
})
const snapRiskCount = computed(() => (snap.value?.items || []).filter(rowIsRisk).length)
const selectedDll = ref(null)
const processDlls = computed(() => {
  const row = snapRow.value
  if (!row) return []
  const mods = row.modules
  if (Array.isArray(mods)) {
    return mods.map((d) => {
      const signed = String(d?.signed || '')
      const path = String(d?.path || '')
      const hot = !!d?.hot || HOT_PATH_RE.test(path)
      const unsigned = !!(signed && /not|unsigned|invalid|hash/i.test(signed) && !/valid/i.test(signed))
      return {
        name: d?.name || '',
        path,
        size: d?.size,
        signed,
        signer: d?.signer || '',
        company: d?.company || '',
        file_version: d?.file_version || '',
        sha256: d?.sha256 || '',
        hot,
        unsigned,
      }
    })
  }
  return []
})
watch(snapRow, () => { selectedDll.value = null })
const HOT_PATH_RE = /\\(temp|tmp|appdata|users\\public|downloads)\\/i
const snapStats = computed(() => {
  const items = snap.value?.items || []
  const total = items.length
  let unsigned = 0
  let hotpath = 0
  let admins = 0
  let risky = 0
  const hotRows = []
  for (const row of items) {
    const signed = String(row.signed || '')
    const path = String(row.path || row.command || row.command_line || row.execute || '')
    const user = String(row.user || row.account || '')
    if (signed && /not|unsigned|invalid|hash/i.test(signed) && !/valid/i.test(signed)) unsigned += 1
    if (HOT_PATH_RE.test(path)) hotpath += 1
    if (/administrator|system|admin/i.test(user)) admins += 1
    if (rowIsRisk(row)) risky += 1
    let tag = ''
    let sev = 'medium'
    if (row.risk_tags && !rowIsNoise(row)) { tag = String(row.risk_tags).split(',')[0]; sev = Number(row.risk_score || 0) >= 40 ? 'high' : 'medium' }
    else if (HOT_PATH_RE.test(path)) { tag = '可疑路径'; sev = 'high' }
    else if (signed && /not|unsigned|invalid/i.test(signed) && !/valid/i.test(signed)) { tag = '未签名'; sev = 'medium' }
    else if (module.value === 'network' && row.remote && !/^127\.|^::1|^0\.0\.0\.0/i.test(String(row.remote))) {
      tag = '外联'; sev = 'info'
    }
    if (tag && hotRows.length < 8) {
      hotRows.push({
        tag, sev, row,
        title: row.name || row.task_name || row.display_name || row.process_name || '条目',
        sub: (path || row.remote || user || row.modules_summary || '').slice(0, 64),
      })
    }
  }
  const flags = []
  if (risky) flags.push({ k: 'r', tone: 'warn', label: `可疑 ${risky}` })
  if (unsigned) flags.push({ k: 'u', tone: 'bad', label: `未签名 ${unsigned}` })
  if (hotpath) flags.push({ k: 'h', tone: 'warn', label: `可疑路径 ${hotpath}` })
  if (module.value === 'process' && admins) flags.push({ k: 'a', tone: 'info', label: `高权限 ${admins}` })
  const sampleRows = []
  for (const row of items.slice(0, 6)) {
    if (hotRows.some((h) => h.row === row)) continue
    sampleRows.push({
      row,
      title: row.name || row.task_name || row.display_name || row.process_name || '条目',
      sub: String(row.path || row.command || row.command_line || row.remote || row.user || row.pid || '').slice(0, 64),
    })
    if (sampleRows.length >= 5) break
  }
  const fields = items[0] ? Object.keys(items[0]).length : 0
  return {
    total,
    fields,
    unsigned: module.value === 'process' || module.value === 'file' || module.value === 'service' ? unsigned : null,
    hotpath: ['process', 'file', 'startup', 'task', 'service'].includes(module.value) ? hotpath : null,
    admins: module.value === 'process' ? admins : null,
    flags,
    hotRows,
    sampleRows,
  }
})
function openHostThreats(a) {
  if (!a) return
  goPage('events')
  eventAgentId.value = a.agent_id
}
function openSelectedHostThreats() {
  const aid = selected.value?.agent_id || ''
  goMenu('events')
  eventAgentId.value = aid
}

function rowTitle(row) {
  if (!row) return '条目'
  return row.name || row.task_name || row.display_name || row.path || row.local || '条目详情'
}

function formatDetail(v) {
  if (v == null || v === '') return '—'
  if (typeof v === 'boolean') return v ? '是' : '否'
  return String(v)
}

function detailGroups(row) {
  if (!row) return []
  const groups = [
    { title: '基本信息', keys: ['name', 'task_name', 'display_name', 'status', 'state', 'enabled', 'pid', 'ppid', 'parent_name', 'process_name', 'user', 'account', 'session_id', 'session', 'source', 'ext', 'proto', 'risk_score', 'risk_tags'] },
    { title: '路径 / 命令', keys: ['path', 'command', 'command_line', 'execute', 'arguments', 'working_directory', 'directory', 'location', 'local', 'remote'] },
    { title: '签名 / 哈希', keys: ['signed', 'signer', 'company', 'file_version', 'sha256'] },
    { title: '模块 / 资源', keys: ['module_count', 'module_third_count', 'modules_summary', 'uptime', 'uptime_sec', 'create_time', 'created', 'modified', 'last_run', 'next_run', 'last_logon', 'last_result', 'memory_mb', 'size', 'size_kb', 'handles'] },
    { title: '其他', keys: [] },
  ]
  const used = new Set(['modules', 'noise'])
  const out = []
  for (const g of groups.slice(0, 4)) {
    const fields = {}
    for (const k of g.keys) {
      if (k in row) {
        fields[k] = row[k]
        used.add(k)
      }
    }
    if (Object.keys(fields).length) out.push({ title: g.title, fields })
  }
  const rest = {}
  for (const [k, v] of Object.entries(row)) {
    if (!used.has(k)) rest[k] = v
  }
  if (Object.keys(rest).length) out.push({ title: '其他字段', fields: rest })
  return out
}

function rowRelatedAlerts(row) {
  if (!row || !selected.value) return []
  const needles = [row.name, row.task_name, row.path, row.command, row.command_line, row.execute]
    .filter(Boolean)
    .map((x) => String(x).toLowerCase())
  if (!needles.length) return []
  return allEvents.value.filter((e) => {
    if (e.agent_id !== selected.value.agent_id) return false
    const blob = `${e.title || ''} ${e.detail || ''}`.toLowerCase()
    return needles.some((n) => n.length >= 4 && blob.includes(n.slice(0, 80)))
  }).slice(0, 5)
}

function openHuntModule(m, q = '') {
  module.value = m
  snapQ.value = q || ''
  if (agents.value[0]) openHost(agents.value[0], 'hosts')
  else goPage('hosts')
}

async function removeEvent(e) {
  if (!e?.id) return
  if (!window.confirm(`删除事件「${e.title}」？`)) return
  try {
    await deleteEvent(e.id)
    if (activeEvent.value?.id === e.id) closeThreat()
    okMsg.value = '事件已删除'
    setTimeout(() => { okMsg.value = '' }, 2000)
    await loadEvents()
  } catch (err) {
    error.value = err?.message || String(err)
  }
}

function short(id) { return String(id || '').slice(0, 8) }
const EVENT_MODULE_LABELS = {
  memory: '内存扫描', kernel: '内核驱动', etw: 'ETW', timeline: '时间线',
  sequence: '行为序列', response: '处置', ioc: '威胁情报', registry: '注册表',
  image: 'DLL / 驱动加载', inject: '注入 / 进程访问', dns: 'DNS', account: '账号与登录',
  audit: '审计日志', script: '脚本执行',
}
function modLabel(m) { return LABELS[m] || EVENT_MODULE_LABELS[m] || m || '' }
function colLabel(c) { return COL_LABELS[c] || c }
function statusLabel(s) { return ({ open: '未处置', closed: '已处置', ignored: '无需处置' })[s] || s }
function sevLabel(s) { return ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' })[s] || s || '—' }
function judgeOf(e) {
  if (/规则命中/.test(e.title || '')) return '规则命中'
  if (/Defender|排除项/.test(e.title || '')) return '防御削弱'
  if (/^注册表|^持久化/.test(e.title || '')) return '注册表变更'
  if (/乱码|编码/.test(e.title || '')) return '数据质量'
  if (/失败|为空/.test(e.title || '')) return '采集异常'
  return '待研判'
}
function cell(row, c) {
  const v = row?.[c]
  if (v == null || v === '') return '—'
  const s = String(v).replace(/\uFFFD/g, '')
  return s.length > 120 ? `${s.slice(0, 118)}…` : s
}
function fmtTime(t) {
  if (!t) return '—'
  return String(t).replace('T', ' ').slice(0, 19)
}

/** 一级导航默认页：跳过会跳到其它 rail 分区的二级项（如检测里的「终端安全概览」→ 概览分区） */
function defaultPageForSection(sectionId) {
  const skipCross = {
    detect: new Set(['overview', 'whitelist', 'malware']),
    rules: new Set(['whitelist']),
    ai: new Set(),
    asset: new Set(),
    deploy: new Set(),
    config: new Set(),
    overview: new Set(),
  }
  const skip = skipCross[sectionId] || new Set()
  for (const g of menuMap[sectionId] || []) {
    for (const m of g.items || []) {
      if (m.adminOnly) continue
      if (!skip.has(m.id)) return m.id
    }
  }
  return null
}

function setSection(id) {
  section.value = id
  selected.value = null
  if (id !== 'detect') {
    activeEvent.value = null
  }
  menuHover.value = true
  const pick = defaultPageForSection(id)
  if (pick) goMenu(pick)
}

function goMenu(id) {
  selected.value = null
  clearListFocus()
  if (id !== 'ai-analyze') stopAiHostsPoll()
  // 跨分区跳转时同步左侧栏
  if (id === 'overview') {
    section.value = 'overview'
    page.value = 'overview'
    softRefresh({ overview: true })
    return
  }
  if (id === 'whitelist') {
    section.value = 'rules'
    page.value = 'rules'
    rulesSection.value = 'whitelist'
    loadWhitelistOnly()
    return
  }
  if (id === 'malware') {
    section.value = 'detect'
    page.value = 'malware'
    eventListReturnPage.value = 'malware'
    focusKey.value = ''
    behaviorCat.value = ''
    eventSevFilter.value = ''
    eventAgentId.value = ''
    activeEvent.value = null
    clearListFocus()
    evtPage.value = 1
    loadEvents(true, true)
    return
  }
  if (['events', 'behaviors', 'attck', 'investigate', 'timeline', 'hunt', 'dns', 'ioc'].includes(id)) section.value = 'detect'
  if (['rules', 'seq'].includes(id)) section.value = 'rules'
  if (id === 'ai-analyze') section.value = 'ai'
  if (['hosts', 'groups'].includes(id)) section.value = 'asset'
  if (id === 'assets') { section.value = 'asset'; id = 'hosts' }
  if (['deploy', 'upgrade', 'audit'].includes(id)) section.value = 'deploy'
  if (['settings', 'policy', 'notify', 'storage', 'accounts'].includes(id)) section.value = 'config'
  if (id === 'accounts') loadEdrUsers()

  if (id === 'events' || id === 'behaviors') {
    activeEvent.value = null
    page.value = id
    if (id === 'events') {
      eventListReturnPage.value = 'events'
      resetEventFilters()
      loadGroups().catch(() => {})
    } else {
      focusKey.value = ''
      eventSevFilter.value = ''
      eventAgentId.value = ''
    }
    loadEvents(true, true)
    return
  }
  page.value = id
  if (id === 'rules') { loadRules(); loadMemoryYara(); loadAgentSyncManifest(); loadWhitelistOnly() }
  if (id === 'settings') { loadSettings(); loadRules() }
  if (id === 'timeline') loadTimeline()
  if (id === 'investigate') {
    // 3 分钟内有结果则复用，避免每次点进都全量重拉
    const fresh = invItems.value.length && Date.now() - lastInvestigateAt < 180000
    if (!fresh) runInvestigate()
  }
  if (id === 'policy') loadPolicyPage()
  if (id === 'hunt') { huntDone.value = false }
  if (id === 'dns') {
    loadGroups().catch(() => {})
    loadDns()
  }
  if (id === 'ioc') loadIoc()
  if (id === 'attck') loadAttckBoard()
  if (id === 'upgrade') loadUpgradePage()
  if (id === 'notify') loadNotify()
  if (id === 'storage') loadStorage()
  if (id === 'seq') loadSeqRules()
  if (id === 'groups') loadGroups()
  if (id === 'audit') loadAudit()
  if (id === 'ai-analyze') loadAiAnalyzePage()
  if (id === 'deploy') { loadRelease(); loadCredentials() }
  if (id === 'assets' || id === 'hosts') refresh()
}

async function loadRules() {
  try {
    const r = await agentRuleStats()
    if (r?.ok) {
      ruleStats.value = r
      agentRules.value = r.items || []
    }
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

async function bulkRulesEnabled(on) {
  const ids = (filteredAgentRules.value || []).map((r) => r.id).filter(Boolean)
  if (!ids.length) return
  rulesBulkBusy.value = true
  try {
    await bulkAgentRulesEnabled({ enabled: !!on, all_filtered: true, rule_ids: ids })
    await loadRules()
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    rulesBulkBusy.value = false
  }
}

async function bulkElasticRules(on) {
  rulesBulkBusy.value = true
  try {
    await bulkAgentRulesEnabled({ enabled: !!on, all_elastic: true })
    await loadRules()
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    rulesBulkBusy.value = false
  }
}

async function bulkElasticEvm(on) {
  rulesBulkBusy.value = true
  try {
    await bulkElasticEvmEnabled({ enabled: !!on, all: true })
    await loadAgentSyncManifest()
    await loadRules()
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    rulesBulkBusy.value = false
  }
}

function shortHash(h) {
  const s = String(h || '')
  if (s.length < 24) return s || '—'
  return `${s.slice(0, 16)}…${s.slice(-8)}`
}

function openRulesMemorySection() {
  rulesSection.value = 'memory'
  if (!memoryYaraPack.value && !memoryYaraBusy.value) loadMemoryYara()
}

function openRulesWhitelistSection() {
  rulesSection.value = 'whitelist'
  loadWhitelistOnly()
}

async function loadWhitelistOnly() {
  try {
    const w = await listWhitelist()
    whitelist.value = w?.items || []
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

/** @param {{ silent?: boolean }} opts — silent 时不占用「刷新同步摘要」按钮，避免 SSE/轮询导致按钮一直闪 */
async function loadAgentSyncManifest(opts = {}) {
  const silent = !!opts.silent
  if (!silent) agentSyncBusy.value = true
  try {
    agentSyncManifest.value = await getAgentSyncManifest()
  } catch {
    if (!silent) agentSyncManifest.value = null
  } finally {
    if (!silent) agentSyncBusy.value = false
  }
}

function shouldRefreshAgentSyncManifest(kind) {
  return kind === 'sync' || kind === 'rules' || kind === 'policy' || kind === 'whitelist' || kind === 'ioc'
    || kind === 'memory_yara' || kind === 'integrations'
}

async function loadAgentIntegrations() {
  agentIntegrationsErr.value = ''
  try {
    agentIntegrations.value = await getAgentIntegrations()
  } catch (e) {
    agentIntegrationsErr.value = e?.message || String(e)
    agentIntegrations.value = null
  }
}

async function toggleAgentIntegrationsPanel() {
  agentIntegrationsOpen.value = !agentIntegrationsOpen.value
  if (agentIntegrationsOpen.value && !agentIntegrations.value?.ok) {
    await loadAgentIntegrations()
  }
}

async function setAgentIntegration(key, on) {
  if (!isAdmin.value || !agentIntegrations.value?.ok) return
  agentIntegrationsBusy.value = true
  agentIntegrationsErr.value = ''
  const defaults = { ...(agentIntegrations.value.defaults || {}), [key]: !!on }
  try {
    const out = await saveAgentIntegrations({ defaults })
    if (out?.ok) {
      agentIntegrations.value = out
    } else {
      await loadAgentIntegrations()
    }
    await loadAgentSyncManifest({ silent: true })
  } catch (e) {
    agentIntegrationsErr.value = e?.message || String(e)
  } finally {
    agentIntegrationsBusy.value = false
  }
}

async function setServerDetection(key, on) {
  if (!isAdmin.value || !agentIntegrations.value?.ok) return
  agentIntegrationsBusy.value = true
  agentIntegrationsErr.value = ''
  const server = { ...(agentIntegrations.value.server || {}), [key]: !!on }
  try {
    const out = await saveAgentIntegrations({ server })
    if (out?.ok) {
      agentIntegrations.value = out
    } else {
      await loadAgentIntegrations()
    }
    await loadAgentSyncManifest({ silent: true })
  } catch (e) {
    agentIntegrationsErr.value = e?.message || String(e)
  } finally {
    agentIntegrationsBusy.value = false
  }
}

async function manualBumpAgentSync() {
  if (!isAdmin.value) return
  agentSyncBumpBusy.value = true
  try {
    const out = await bumpAgentSync('manual')
    if (out?.manifest) agentSyncManifest.value = out.manifest
    else await loadAgentSyncManifest({ silent: true })
  } catch (e) {
    agentIntegrationsErr.value = e?.message || String(e)
  } finally {
    agentSyncBumpBusy.value = false
  }
}

async function loadMemoryYara() {
  memoryYaraBusy.value = true
  memoryYaraErr.value = ''
  try {
    memoryYaraPack.value = await getMemoryYaraRules()
    if (!memoryYaraPack.value?.ok) {
      memoryYaraErr.value = memoryYaraPack.value?.error || '规则包不可用'
    }
  } catch (e) {
    memoryYaraErr.value = e?.message || String(e)
    memoryYaraPack.value = null
  } finally {
    memoryYaraBusy.value = false
  }
}

async function applyMemoryYaraControlsPatch(patch) {
  if (!isAdmin.value) return
  memoryYaraControlsBusy.value = true
  memoryYaraErr.value = ''
  try {
    const out = await saveMemoryYaraControls(patch)
    if (out?.pack?.ok) {
      memoryYaraPack.value = out.pack
    } else {
      await loadMemoryYara()
    }
    loadAgentSyncManifest(true)
  } catch (e) {
    memoryYaraErr.value = e?.message || String(e)
  } finally {
    memoryYaraControlsBusy.value = false
  }
}

function setMemoryYaraGroup(key, on) {
  const groups = { ...(memoryYaraPack.value?.controls?.groups || {}), [key]: !!on }
  applyMemoryYaraControlsPatch({ groups })
}

function toggleMemoryYaraStringRule(r, on) {
  const cur = memoryYaraPack.value?.controls?.disabled_string_rule_ids || []
  let ids = [...cur]
  const id = String(r?.id || '')
  if (!id) return
  if (on) {
    ids = ids.filter((x) => x !== id)
  } else if (!ids.includes(id)) {
    ids.push(id)
  }
  applyMemoryYaraControlsPatch({ disabled_string_rule_ids: ids })
}

function setAllMemoryYaraStringRules(on) {
  if (!isAdmin.value) return
  if (on) {
    applyMemoryYaraControlsPatch({ disabled_string_rule_ids: [] })
    return
  }
  const ids = (memoryYaraPack.value?.items || [])
    .map((r) => String(r?.id || '').trim())
    .filter(Boolean)
  applyMemoryYaraControlsPatch({ disabled_string_rule_ids: ids })
}

function startCreateRule() {
  ruleCreating.value = true
  editingRule.value = null
  ruleFormError.value = ''
  ruleForm.value = emptyRuleForm()
}

async function startEditRule(r) {
  ruleCreating.value = false
  editingRule.value = r
  ruleFormError.value = ''
  elasticOfficialDetail.value = null
  const exts = [...(r.file_exts || [])]
  const isSensor = !!(r.builtin || r.source === 'sensor')
  let patterns = (r.patterns || []).filter((p) => p && p !== '*')
  if (isSensor && !patterns.length && r.summary_contains) {
    patterns = [r.summary_contains]
  }
  ruleForm.value = {
    title: r.title || '',
    severity: r.severity || 'medium',
    modules: [...(r.modules || ['process'])],
    fieldsText: (r.fields || []).join(','),
    patternsText: patterns.join('\n'),
    fileExts: exts,
    fileExtsText: exts.join(','),
    signedFilter: r.signed_filter || '',
    pathPrefixesText: (r.path_prefixes || []).join(','),
    match: r.match || 'substring',
    enabled: r.enabled !== false,
    note: r.note || '',
    etype: r.etype || '',
  }
  if (isElasticRule(r)) {
    elasticOfficialBusy.value = true
    try {
      elasticOfficialDetail.value = await getElasticDetectionRuleDetail(r.id)
    } catch (e) {
      elasticOfficialDetail.value = { ok: false, error: e?.message || String(e) }
    } finally {
      elasticOfficialBusy.value = false
    }
  }
}

function cancelRuleForm() {
  ruleCreating.value = false
  editingRule.value = null
  ruleFormError.value = ''
  ruleForm.value = emptyRuleForm()
}

function applyRuleTemplate(t) {
  ruleForm.value = {
    ...emptyRuleForm(),
    title: t.title,
    severity: t.severity,
    modules: [...t.modules],
    fieldsText: t.fieldsText,
    patternsText: t.patternsText,
    fileExts: [...(t.fileExts || [])],
    fileExtsText: (t.fileExts || []).join(','),
    signedFilter: t.signedFilter || '',
    pathPrefixesText: (t.pathPrefixes || []).join(','),
    match: t.match || 'substring',
    note: t.note || '',
    enabled: true,
  }
}

function toggleRuleModule(m) {
  const arr = ruleForm.value.modules
  const i = arr.indexOf(m)
  if (i >= 0) {
    if (arr.length <= 1) return
    arr.splice(i, 1)
  } else {
    arr.push(m)
  }
}

function toggleFileExt(ext) {
  const arr = ruleForm.value.fileExts
  const i = arr.indexOf(ext)
  if (i >= 0) arr.splice(i, 1)
  else arr.push(ext)
  ruleForm.value.fileExtsText = arr.join(',')
}

function syncFileExtsFromText() {
  const arr = String(ruleForm.value.fileExtsText || '')
    .split(/[,;\s]+/)
    .map((x) => x.trim().replace(/^\./, '').toLowerCase())
    .filter(Boolean)
  ruleForm.value.fileExts = [...new Set(arr)]
  ruleForm.value.fileExtsText = ruleForm.value.fileExts.join(',')
}

function toggleField(f) {
  const parts = String(ruleForm.value.fieldsText || '')
    .split(/[,;\s]+/)
    .map((x) => x.trim())
    .filter(Boolean)
  const i = parts.indexOf(f)
  if (i >= 0) parts.splice(i, 1)
  else parts.push(f)
  ruleForm.value.fieldsText = parts.join(',')
}

function buildRulePayload() {
  syncFileExtsFromText()
  const f = ruleForm.value
  return {
    title: f.title.trim(),
    severity: f.severity,
    modules: f.modules,
    fields: f.fieldsText,
    patterns: f.patternsText,
    file_exts: f.fileExts,
    signed_filter: f.signedFilter || '',
    path_prefixes: f.pathPrefixesText,
    match: f.match,
    enabled: f.enabled,
    note: f.note,
  }
}

async function saveRuleForm() {
  ruleSaving.value = true
  ruleFormError.value = ''
  try {
    if (isEditingSensor.value && editingRule.value?.id) {
      const f = ruleForm.value
      syncFileExtsFromText()
      const patterns = String(f.patternsText || '')
        .split(/\n/)
        .map((x) => x.trim())
        .filter(Boolean)
      if (!f.title?.trim()) throw new Error('请填写标题')
      if (!patterns.length) throw new Error('请至少填写一条摘要关键字')
      await updateAgentRule(editingRule.value.id, {
        title: f.title.trim(),
        severity: f.severity,
        note: f.note,
        enabled: f.enabled,
        etype: String(f.etype || '').trim(),
        patterns,
        match: f.match || 'substring',
        summary_contains: patterns[0],
        fields: f.fieldsText,
        file_exts: f.fileExts,
        signed_filter: f.signedFilter || '',
        path_prefixes: f.pathPrefixesText,
      })
      okMsg.value = '内置传感器已更新'
      setTimeout(() => { okMsg.value = '' }, 2000)
      const id = editingRule.value.id
      await loadRules()
      const again = agentRules.value.find((x) => x.id === id)
      if (again) startEditRule(again)
      return
    }
    const payload = buildRulePayload()
    if (ruleCreating.value) {
      await createAgentRule(payload)
      okMsg.value = '规则已创建'
    } else if (editingRule.value?.id) {
      await updateAgentRule(editingRule.value.id, payload)
      okMsg.value = '规则已更新'
    }
    setTimeout(() => { okMsg.value = '' }, 2000)
    cancelRuleForm()
    await loadRules()
  } catch (e) {
    ruleFormError.value = e?.message || String(e)
  } finally {
    ruleSaving.value = false
  }
}

async function resetSensorRule() {
  if (!editingRule.value?.id) return
  if (!window.confirm('恢复该内置传感器为出厂默认配置？')) return
  ruleSaving.value = true
  ruleFormError.value = ''
  try {
    await updateAgentRule(editingRule.value.id, { reset_default: true })
    okMsg.value = '已恢复默认'
    setTimeout(() => { okMsg.value = '' }, 2000)
    const id = editingRule.value.id
    await loadRules()
    const again = agentRules.value.find((x) => x.id === id)
    if (again) startEditRule(again)
  } catch (e) {
    ruleFormError.value = e?.message || String(e)
  } finally {
    ruleSaving.value = false
  }
}

async function toggleRule(r, enabled) {
  try {
    const evmOnly = r?.rule_channel === 'evm' || /\.(evm|fim)$/i.test(String(r?.id || ''))
    if (evmOnly) {
      await bulkElasticEvmEnabled({ enabled: !!enabled, rule_ids: [r.id] })
    } else {
      await patchAgentRule(r.id, { enabled })
    }
    await loadRules()
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

async function removeRule(r) {
  if (r?.builtin || r?.source === 'sensor') {
    error.value = '内置传感器规则不能删除，请关闭启用开关'
    return
  }
  if (!window.confirm(`删除规则「${r.title}」？`)) return
  try {
    await deleteAgentRule(r.id)
    if (editingRule.value?.id === r.id) cancelRuleForm()
    await loadRules()
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

function goEventsWith({ focus = '', agent = '' } = {}) {
  goPage('events')
  focusKey.value = focus
  eventTypeFilter.value = focus
  eventAgentId.value = agent
  eventFiltersOn.value = { ...eventFiltersOn.value, type: focus || '' }
}
function goPage(id) {
  if (id === 'events') {
    section.value = 'detect'
    page.value = 'events'
    resetEventFilters()
    loadGroups().catch(() => {})
    loadEvents(true, true)
  } else if (id === 'hosts') {
    section.value = 'asset'
    page.value = 'hosts'
  } else {
    page.value = id
  }
}

function eventIntelText(e) {
  const root = parseEventEvidence(e)
  const flat = evidenceFlatOf(root)
  return [
    e?.title, e?.module, e?.hostname,
    flat.ioc_value, flat.ioc_type, flat.domain, flat.query,
    flat.remote, flat.remote_ip, flat.malware, flat.intel_source, flat.matched_from,
    root.ioc_value, root.domain, root.query, root.remote, root.remote_ip, root.malware,
  ].filter(Boolean).join(' ').toLowerCase()
}
function eventSearchText(e) {
  return [
    eventIntelText(e),
    eventCmdSummary(e),
    eventFileHint(e),
  ].join(' ').toLowerCase()
}
function applyEventFilters() {
  eventTypeFilter.value = eventTypeFilter.value || ''
  focusKey.value = eventTypeFilter.value
  eventFiltersOn.value = {
    name: eventQName.value.trim().toLowerCase(),
    ioc: eventIocQ.value.trim().toLowerCase(),
    group: eventGroupId.value || '',
    type: eventTypeFilter.value || '',
    sev: eventSevFilter.value || '',
  }
}
function resetEventFilters() {
  eventQName.value = ''
  eventIocQ.value = ''
  eventGroupId.value = ''
  eventTypeFilter.value = ''
  eventSevFilter.value = ''
  eventAgentId.value = ''
  focusKey.value = ''
  eventFiltersOn.value = { name: '', ioc: '', group: '', type: '', sev: '' }
}
function clearEventFilters() {
  resetEventFilters()
}
function toggleFocusCat(key) {
  const next = focusKey.value === key ? '' : key
  focusKey.value = next
  eventTypeFilter.value = next
  eventFiltersOn.value = { ...eventFiltersOn.value, type: next }
}
/** 点击告警日志数 → 日志调查，带上主机与 IP/域名关键词 */
function openEventLogHits(e) {
  if (!e) return
  const root = parseEventEvidence(e)
  const flat = evidenceFlatOf(root)
  let q = String(
    flat.ioc_value || flat.domain || flat.query || flat.remote_ip || flat.remote || '',
  ).trim()
  if (!q) {
    const art = eventTitleArtifact(e.title)
    q = art || String(e.title || '').replace(/^情报\s*IOC\s*命中:\s*/i, '').slice(0, 96)
  }
  invQ.value = q
  invRange.value = '7d'
  invFilters.value = {
    nature: '', etype: '', hostname: e.hostname || '',
    path: '', hash_q: '', entity: '', tactic: '', os: '',
  }
  invNatureTab.value = ''
  lastInvestigateAt = 0
  goMenu('investigate')
  runInvestigate()
}

let overviewReloadTimer = null
function scheduleOverviewReload() {
  if (page.value !== 'overview') return
  if (overviewReloadTimer) return
  overviewReloadTimer = setTimeout(async () => {
    overviewReloadTimer = null
    try {
      await loadOverview()
    } catch { /* ignore */ }
  }, 400)
}

let lastSoftEventsAt = 0
async function softRefresh({ snap = false, rules = false, overview = false, events = false } = {}) {
  try {
    const list = await listAgents(45)
    agents.value = list?.items || []
    if (selected.value) {
      const still = agents.value.find((a) => a.agent_id === selected.value.agent_id)
      selected.value = still || null
      if (still && (snap || page.value === 'hosts' || page.value === 'assets')) {
        if (hostTabGroup.value === 'remote') {
          loadHostRemoteCommands()
        } else {
          await loadSnap(module.value, { silent: true, keepRow: true })
        }
      }
    }
    // 告警列表：默认不每几秒全量重拉（会因 updated_at 重排，看起来像「事件名称一直在变」）
    // 仅：显式 events / 总览页 / 距上次超过 90s / 列表仍空
    const onAlertPage = page.value === 'events' || page.value === 'malware' || page.value === 'behaviors'
    const eventsDue = Date.now() - lastSoftEventsAt > 90000
    if (events || overview || page.value === 'overview' || !allEvents.value.length || (onAlertPage && eventsDue)) {
      await loadEvents(false)
      lastSoftEventsAt = Date.now()
    }
    if (overview || page.value === 'overview') {
      scheduleOverviewReload()
    }
    if (rules) {
      try {
        const rs = await agentRuleStats()
        if (rs?.ok) {
          ruleStats.value = rs
          if (Array.isArray(rs.items)) agentRules.value = rs.items
        }
      } catch { /* ignore */ }
    }
    lastSyncAt.value = Date.now()
    liveOk.value = true
  } catch {
    liveOk.value = false
  }
}

async function refresh() {
  loading.value = true
  error.value = ''
  // 威胁事件与终端列表并行，避免「先等 agents 再拉告警」造成空白
  const eventsP = loadEvents(false)
  try {
    const [list, proto, rs] = await Promise.all([
      listAgents(45),
      agentProtocol().catch(() => ({})),
      agentRuleStats().catch(() => null),
    ])
    agents.value = list?.items || []
    if (proto?.modules?.length) modules.value = proto.modules
    if (rs?.ok) {
      ruleStats.value = rs
      if (Array.isArray(rs.items)) agentRules.value = rs.items
    }
    if (selected.value) {
      const still = agents.value.find((a) => a.agent_id === selected.value.agent_id)
      selected.value = still || null
      if (still) {
        if (hostTabGroup.value === 'remote') loadHostRemoteCommands()
        else await loadSnap(module.value, { silent: false, keepRow: true })
      }
    }
    await Promise.all([eventsP, loadOverview(), loadSettings()])
    maybeAutoEnrichEvents()
    listTimeline({ limit: 80 }).then((tl) => {
      timelineItems.value = tl?.items || []
    }).catch(() => {})
    lastSyncAt.value = Date.now()
    liveOk.value = true
  } catch (e) {
    error.value = e?.message || String(e)
    liveOk.value = false
    await eventsP.catch(() => {})
  } finally {
    loading.value = false
  }
}

function toggleEventSort(key) {
  if (eventSort.value.key === key) {
    eventSort.value = { key, dir: eventSort.value.dir === 'asc' ? 'desc' : 'asc' }
  } else {
    eventSort.value = { key, dir: key === 'severity' ? 'desc' : 'desc' }
  }
}
function sortMark(key) {
  if (eventSort.value.key !== key) return '↕'
  return eventSort.value.dir === 'asc' ? '↑' : '↓'
}
function eventLogCount(e) {
  const n = Number(e?.hit_count)
  if (Number.isFinite(n) && n > 0) return Math.floor(n)
  // 兼容旧数据：同主机同标题仍打开的条数
  const title = e?.title || ''
  const aid = e?.agent_id || ''
  return allEvents.value.filter((x) => x.agent_id === aid && x.title === title).length || 1
}
function toggleEventSelect(id) {
  const set = new Set(selectedEventIds.value)
  if (set.has(id)) set.delete(id)
  else set.add(id)
  selectedEventIds.value = [...set]
}
function toggleSelectAllEvents(ev) {
  if (ev?.target?.checked) {
    const pageIds = new Set(pagedEvents.value.map((e) => e.id))
    selectedEventIds.value = [...new Set([...selectedEventIds.value, ...pageIds])]
  } else {
    const pageIds = new Set(pagedEvents.value.map((e) => e.id))
    selectedEventIds.value = selectedEventIds.value.filter((id) => !pageIds.has(id))
  }
}
async function removeSelectedEvents() {
  const ids = [...selectedEventIds.value]
  if (!ids.length) return
  if (!window.confirm(`删除选中的 ${ids.length} 条事件？`)) return
  for (const id of ids) {
    try { await deleteEvent(id) } catch { /* continue */ }
  }
  selectedEventIds.value = []
  await loadEvents(false)
}
async function removeAllEvents() {
  const filtered = eventFiltersActive.value
  const n = filtered ? filteredEvents.value.length : allEvents.value.length
  const scope = filtered ? '当前筛选结果中的' : '全部'
  if (!window.confirm(`删除${scope} ${n} 条威胁事件？此操作不可恢复。\n已删除的告警不会再从时间线补回；之后的新检出仍会正常告警。`)) return
  try {
    let r
    const on = eventFiltersOn.value || {}
    if (on.name || on.ioc || on.group || on.type || focusKey.value) {
      let deleted = 0
      for (const e of [...filteredEvents.value]) {
        try { await deleteEvent(e.id); deleted += 1 } catch { /* continue */ }
      }
      r = { deleted }
    } else {
      r = await deleteEventsBulk({ agentId: eventAgentId.value, severity: on.sev || eventSevFilter.value })
    }
    selectedEventIds.value = []
    if (activeEvent.value) activeEvent.value = null
    okMsg.value = `已删除 ${r?.deleted ?? 0} 条威胁事件`
    setTimeout(() => { okMsg.value = '' }, 2500)
    await loadEvents(false)
  } catch (e) {
    error.value = e?.message || String(e)
  }
}
async function jumpToPid(pid) {
  const n = Number(pid)
  if (!n) return
  await loadSnap('process', { silent: false, keepRow: false })
  const row = (snap.value?.items || []).find((r) => Number(r.pid) === n)
  if (row) snapRow.value = row
}

const respPendingCount = computed(() =>
  respCommands.value.filter((c) => c.status === 'pending' || c.status === 'sent').length,
)

function actionLabel(a) {
  return ({
    kill_process: '结束进程',
    quarantine_file: '隔离文件',
    isolate_network: '网络隔离',
    unisolate_network: '解除隔离',
    refresh_modules: '刷新模块',
    upgrade: '升级',
    scan_memory: '内存扫描',
    restore_file: '回滚隔离',
    rollback_upgrade: '回滚升级',
    uninstall_agent: '远程卸载',
    reg_read: '读注册表',
    fs_list: '列目录',
    fs_volumes: '枚举盘符',
    fs_stat: '文件信息',
    fs_read: '读文件',
    run_cmd: '执行命令',
    live_query: 'Live Query',
    cancel_upgrade: '取消升级',
    shell_open: 'Shell 开启',
    shell_write: 'Shell 输入',
    shell_poll: 'Shell 输出',
    shell_close: 'Shell 关闭',
  })[a] || a
}

function parseJsonSafe(raw) {
  if (!raw) return {}
  try { return typeof raw === 'string' ? JSON.parse(raw) : raw } catch { return {} }
}

async function restoreQuarantined(c) {
  const res = parseJsonSafe(c.result_json)
  const original = res.original || parseJsonSafe(c.params_json).path
  if (!res.dest && !original) {
    error.value = '该指令结果中没有隔离位置，无法回滚'
    return
  }
  if (!window.confirm(`确认把隔离文件恢复到原位置？\n${original || ''}`)) return
  try {
    await createAgentCommand(c.agent_id, 'restore_file', { dest: res.dest || '', original: original || '' })
    okMsg.value = '回滚指令已下发'
    await loadRespCommands()
    startRespPoll()
    if (hostTabGroup.value === 'remote') {
      await loadHostRemoteCommands()
      startHostRemotePoll()
    }
  } catch (e) { error.value = e?.message || String(e) }
}
function cmdStatusLabel(s) {
  return ({ pending: '等待下发', sent: '已送达执行中', done: '成功', failed: '失败' })[s] || s
}
function shortJson(raw) {
  if (!raw) return '—'
  try {
    const o = typeof raw === 'string' ? JSON.parse(raw) : raw
    const t = JSON.stringify(o)
    return t.length > 80 ? `${t.slice(0, 80)}…` : t
  } catch {
    return String(raw).slice(0, 80)
  }
}

function friendlyCmdResult(action, raw) {
  const o = parseJsonSafe(raw)
  if (action === 'kill_process') {
    if (o.killed || o.ok) return `已终止进程 PID ${o.pid ?? '—'}`
    if (o.output) return String(o.output).slice(0, 120)
  }
  if (action === 'quarantine_file') {
    if (o.dest || o.original) return `已隔离至 ${o.dest || o.original}`
  }
  if (action === 'isolate_network') return o.ok === false ? '网络隔离失败' : '终端已网络隔离'
  if (action === 'unisolate_network') return o.ok === false ? '解除隔离失败' : '已解除网络隔离'
  if (action === 'scan_memory') {
    return `扫描 ${o.scanned ?? 0} 个进程，发现 ${o.finding_count ?? 0} 处可疑`
  }
  if (action === 'live_query') {
    const n = o.row_count ?? (Array.isArray(o.rows) ? o.rows.length : 0)
    return `${o.table || '表'} · ${n} 行`
  }
  if (action === 'restore_file') return o.restored ? `已回滚：${o.restored}` : '隔离回滚完成'
  if (action === 'rollback_upgrade') return '升级回滚已执行'
  if (action === 'upgrade') return o.version ? `升级至 ${o.version}` : '升级指令已执行'
  if (o.output) return String(o.output).slice(0, 120)
  if (o.msg) return String(o.msg).slice(0, 120)
  if (o.error) return String(o.error).slice(0, 120)
  return '详见「处置结果」页签'
}

function dismissRespToast() {
  respToast.value = null
  if (respToastTimer) {
    clearTimeout(respToastTimer)
    respToastTimer = null
  }
}

function showRespToast(cls, title, detail, { sticky = false, ms = 4200 } = {}) {
  respToast.value = { cls, title, detail }
  if (respToastTimer) clearTimeout(respToastTimer)
  if (sticky) return
  respToastTimer = setTimeout(() => {
    respToast.value = null
    respToastTimer = null
  }, ms)
}

function stopHostRemotePoll() {
  if (hostRemotePollTimer) {
    clearInterval(hostRemotePollTimer)
    hostRemotePollTimer = null
  }
}

function stopHostRemoteShellPoll() {
  if (hostRemoteShellPollTimer) {
    clearInterval(hostRemoteShellPollTimer)
    hostRemoteShellPollTimer = null
  }
}

function hostRemoteResultOf(raw) {
  const r = parseJsonSafe(raw)
  if (r?.error && r.result && typeof r.result === 'object' && !Array.isArray(r.result)) {
    return { ...r.result, _error: r.error }
  }
  return r
}

function hostRemoteCmdError(c) {
  const r = hostRemoteResultOf(c?.result_json)
  return r.error || r._error || friendlyCmdResult(c?.action, c?.result_json) || '执行失败'
}

async function hostRemoteWaitCommand(cmdId, timeoutMs = 120000) {
  const want = String(cmdId || '').trim()
  if (!want) return { ok: false, error: '指令未创建（需管理员账号，且策略允许 Shell）' }
  const start = Date.now()
  let polls = 0
  while (Date.now() - start < timeoutMs) {
    await new Promise((r) => setTimeout(r, polls < 3 ? 400 : 900))
    polls += 1
    await loadHostRemoteCommands()
    const c = hostRemoteCommands.value.find((x) => String(x.id) === want)
    if (!c) continue
    if (c.status === 'done') return { ok: true, result: hostRemoteResultOf(c.result_json), cmd: c }
    if (c.status === 'failed' || c.status === 'expired') {
      return { ok: false, error: hostRemoteCmdError(c), cmd: c }
    }
  }
  return { ok: false, error: '等待终端执行超时（Agent 是否在线、是否已升级支持 Shell？）' }
}

function hostLiveQueryCell(row, col) {
  const v = row?.[col]
  if (v == null || v === '') return '—'
  if (typeof v === 'object') return JSON.stringify(v).slice(0, 120)
  return String(v).slice(0, 200)
}

async function hostLiveQueryRun() {
  hostLiveQueryRows.value = []
  hostLiveQueryMeta.value = null
  const lim = Math.min(500, Math.max(10, Number(hostLiveQueryLimit.value) || 200))
  hostLiveQueryLimit.value = lim
  const done = await hostRemoteExec('live_query', { table: hostLiveQueryTable.value, limit: lim }, { timeoutMs: 180000 })
  loadLiveQueryAudit()
  if (!done?.ok) return
  const res = done.result || {}
  hostLiveQueryRows.value = Array.isArray(res.rows) ? res.rows : []
  hostLiveQueryMeta.value = {
    table: res.table || hostLiveQueryTable.value,
    row_count: res.row_count ?? hostLiveQueryRows.value.length,
    schema: res.schema || 'forensic_v1',
  }
  okMsg.value = `Live Query ${hostLiveQueryMeta.value.table}：${hostLiveQueryMeta.value.row_count} 行`
  setTimeout(() => { okMsg.value = '' }, 2500)
}

function hostLiveQueryExport() {
  const blob = new Blob([JSON.stringify({ meta: hostLiveQueryMeta.value, rows: hostLiveQueryRows.value }, null, 2)], { type: 'application/json' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `live-query-${hostLiveQueryTable.value}-${Date.now()}.json`
  a.click()
  URL.revokeObjectURL(a.href)
}

async function hostRemoteExec(action, params, { timeoutMs = 120000, busy = true, refreshCmdLog = true } = {}) {
  const a = selected.value
  if (!a?.agent_id) return null
  if (!a.online) {
    error.value = '终端离线，无法下发远程运维指令'
    return null
  }
  if (busy) hostRemoteBusy.value = true
  try {
    const r = await createAgentCommand(a.agent_id, action, params)
    if (!r?.ok) {
      const msg = r?.error || '创建指令失败（需管理员且策略允许）'
      if (busy) error.value = msg
      return { ok: false, error: msg }
    }
    if (refreshCmdLog) startHostRemotePoll()
    const done = await hostRemoteWaitCommand(r?.id, timeoutMs)
    if (!done.ok && busy) error.value = done.error || '执行失败'
    return done
  } catch (e) {
    const msg = e?.message || String(e)
    if (busy) error.value = msg
    return { ok: false, error: msg }
  } finally {
    if (busy) hostRemoteBusy.value = false
  }
}

function hostRemoteShellAppend(kind, text) {
  const t = String(text ?? '').trimEnd()
  if (!t) return
  hostRemoteShellLines.value.push({ kind, text: t })
  nextTick(() => {
    const el = hostRemoteShellViewRef.value
    if (el) el.scrollTop = el.scrollHeight
  })
}

function hostRemoteFmtSize(n) {
  const x = Number(n)
  if (!Number.isFinite(x) || x < 0) return '—'
  if (x < 1024) return `${x} B`
  if (x < 1024 * 1024) return `${(x / 1024).toFixed(1)} KB`
  if (x < 1024 * 1024 * 1024) return `${(x / 1024 / 1024).toFixed(1)} MB`
  return `${(x / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function hostRemoteFsNorm(p) {
  return String(p || '').replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase()
}

function hostRemoteFsSamePath(a, b) {
  const x = hostRemoteFsNorm(a)
  const y = hostRemoteFsNorm(b)
  if (!x || !y) return false
  return x === y
}

function hostRemoteFsJoin(base, name) {
  const b = String(base || '').replace(/\\+$/, '')
  return `${b}\\${name}`
}

function hostRemoteFsFind(nodes, path) {
  const want = hostRemoteFsNorm(path)
  for (const n of nodes || []) {
    if (hostRemoteFsNorm(n.path) === want) return n
    const hit = hostRemoteFsFind(n.children, path)
    if (hit) return hit
  }
  return null
}

function hostRemoteFsNodeFromEntry(parentPath, e) {
  const path = hostRemoteFsJoin(parentPath, e.name)
  return {
    path,
    name: e.name,
    label: e.name,
    dir: true,
    child_count: e.child_count ?? null,
    expanded: false,
    loaded: false,
    children: [],
  }
}

function hostRemoteFsAttach(path, entries) {
  const node = hostRemoteFsFind(hostRemoteFsRoots.value, path)
  if (!node) return
  node.loaded = true
  node.expanded = true
  if (!hostRemoteFsTruncated.value || node.child_count == null) node.child_count = entries.length
  const prev = new Map((node.children || []).map((c) => [hostRemoteFsNorm(c.path), c]))
  node.children = entries.filter((e) => e.dir).map((e) => {
    const childPath = hostRemoteFsJoin(path, e.name)
    const old = prev.get(hostRemoteFsNorm(childPath))
    if (old) {
      old.child_count = e.child_count ?? old.child_count
      return old
    }
    return hostRemoteFsNodeFromEntry(path, e)
  })
}

function hostRemoteFsRootsFromEntries(entries) {
  return (entries || []).map((d) => {
    const path = String(d.path || d.name || '')
    const letter = d.drive || path.replace(/:\\?$/, '')
    return {
      path: path.endsWith('\\') ? path : `${path}\\`,
      name: letter,
      label: String(letter).endsWith(':') ? letter : `${letter}:`,
      dir: true,
      child_count: d.child_count ?? null,
      expanded: false,
      loaded: false,
      children: [],
    }
  }).filter((n) => n.path && n.path.length >= 3)
}

function hostRemoteFsNormalizePath(p) {
  let s = String(p || '').trim().replace(/\//g, '\\')
  if (/^[a-zA-Z]:$/.test(s)) s += '\\'
  return s
}

async function hostRemoteFsDrivesFromCmd() {
  let done = await hostRemoteExec('run_cmd', {
    command: 'wmic logicaldisk get name',
    timeout_sec: 25,
  }, { timeoutMs: 35000, busy: false })
  let text = String(done?.result?.output || '')
  if (!text.trim()) {
    done = await hostRemoteExec('run_cmd', {
      command: 'powershell -noprofile -command "Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Root }"',
      timeout_sec: 25,
    }, { timeoutMs: 35000, busy: false })
    text = String(done?.result?.output || '')
  }
  const seen = new Set()
  const entries = []
  for (const m of text.matchAll(/[A-Za-z]:\\/g)) {
    const path = m[0].toUpperCase()
    if (seen.has(path)) continue
    seen.add(path)
    entries.push({ path, drive: path.slice(0, 1), name: path, dir: true })
  }
  return entries
}

async function hostRemoteFsDiscoverByList() {
  const entries = []
  for (const letter of 'CDEFGHIJKLMNOPQRSTUVWXYZAB') {
    const path = `${letter}:\\`
    const done = await hostRemoteExec('fs_list', { path, max_entries: 1 }, { timeoutMs: 12000, busy: false })
    if (done?.ok) entries.push({ path, drive: letter, name: path, dir: true })
  }
  return entries
}

async function hostRemoteFsLoadVolumes() {
  if (!selected.value?.online) return
  hostRemoteFsHint.value = ''
  const done = await hostRemoteExec('fs_volumes', {}, { timeoutMs: 25000, busy: false })
  let entries = done?.ok ? (done.result?.entries || []) : []
  if (!entries.length) {
    entries = await hostRemoteFsDrivesFromCmd()
    if (entries.length) {
      hostRemoteFsHint.value = '当前 Agent 较旧，已用 wmic/PowerShell 列出磁盘。'
    }
  }
  if (!entries.length) {
    entries = await hostRemoteFsDiscoverByList()
    if (entries.length) hostRemoteFsHint.value = '已通过逐盘 fs_list 探测盘符（无需 run_cmd）。'
  }
  hostRemoteFsDrives.value = entries
  hostRemoteFsRoots.value = hostRemoteFsRootsFromEntries(entries)
  if (!hostRemoteFsRoots.value.length) {
    hostRemoteFsHint.value = '没有读到盘符。确认终端在线且已开启远程运维，或手动输入 C:\\ 后点刷新。'
    return
  }
  const first = hostRemoteFsRoots.value[0]
  hostRemoteFsPath.value = first.path
  await hostRemoteFsBrowse()
}

async function hostRemoteFsToggle(node) {
  if (!node?.path) return
  hostRemoteFsPath.value = node.path
  if (node.loaded && node.expanded) {
    node.expanded = false
    return
  }
  node.expanded = true
  await hostRemoteFsBrowse()
}

function hostRemoteFsUp() {
  let p = String(hostRemoteFsPath.value || '').replace(/\\+$/, '')
  if (!p) return
  const i = p.lastIndexOf('\\')
  if (i <= 2) hostRemoteFsPath.value = `${p.slice(0, 2)}\\`
  else hostRemoteFsPath.value = p.slice(0, i)
  hostRemoteFsBrowse()
}

async function hostRemoteFsBrowse() {
  hostRemoteFsPreview.value = ''
  const path = hostRemoteFsNormalizePath(hostRemoteFsPath.value)
  hostRemoteFsPath.value = path
  const atDriveRoot = /^[A-Za-z]:$/.test(path.replace(/\\+$/, ''))
  const done = await hostRemoteExec('fs_list', {
    path,
    max_entries: 200,
    count_dirs: atDriveRoot,
  }, { timeoutMs: 120000 })
  if (!done?.ok) {
    hostRemoteFsHint.value = done?.error || '列目录失败（检查路径、策略是否允许远程运维）'
    hostRemoteFsEntries.value = []
    return
  }
  hostRemoteFsHint.value = ''
  const entries = [...(done.result?.entries || [])]
  entries.sort((a, b) => {
    if (!!a.dir !== !!b.dir) return a.dir ? -1 : 1
    return String(a.name || '').localeCompare(String(b.name || ''), 'zh')
  })
  hostRemoteFsEntries.value = entries
  hostRemoteFsTruncated.value = !!done.result?.truncated
  hostRemoteFsAttach(hostRemoteFsPath.value, entries)
}

function hostRemoteFsEnter(e) {
  if (!e?.name) return
  const base = hostRemoteFsPath.value.replace(/\\+$/, '')
  const next = e.dir ? `${base}\\${e.name}` : `${base}\\${e.name}`
  hostRemoteFsPath.value = next
  if (e.dir) hostRemoteFsBrowse()
  else {
    hostRemoteForm.value.path = next
    hostRemoteFsRead()
  }
}

async function hostRemoteFsRead() {
  const path = String(hostRemoteFsPath.value || '').trim()
  if (!path) return
  const stat = await hostRemoteExec('fs_stat', { path }, { timeoutMs: 60000, busy: false })
  if (stat?.ok && stat.result?.dir) {
    error.value = '当前路径是目录，请进入目录后双击文件，或选中文件再点「读文件」'
    hostRemoteFsPreview.value = ''
    return
  }
  const done = await hostRemoteExec('fs_read', { path, max_bytes: 65536 })
  if (done?.ok) {
    const r = done.result || {}
    hostRemoteFsPreview.value = r.text || r.hex_preview || JSON.stringify(r, null, 2)
  } else if (done?.error) {
    error.value = done.error
    hostRemoteFsPreview.value = ''
  }
}

function hostRemoteRegApplyShortcut(s) {
  hostRemoteReg.value.hive = s.hive
  hostRemoteReg.value.key = s.key
  hostRemoteReg.value.value = ''
  if (selected.value?.online) hostRemoteRegLoad()
}

function hostRemoteRegOpenSubkey(sk) {
  const base = String(hostRemoteReg.value.key || '').replace(/\\+$/, '')
  hostRemoteReg.value.key = base ? `${base}\\${sk}` : sk
  hostRemoteReg.value.value = ''
  hostRemoteRegLoad()
}

function hostRemoteRegUp() {
  const k = String(hostRemoteReg.value.key || '').replace(/\\+$/, '')
  const i = k.lastIndexOf('\\')
  if (i < 0) return
  hostRemoteReg.value.key = k.slice(0, i)
  hostRemoteReg.value.value = ''
}

async function hostRemoteRegLoad() {
  hostRemoteRegResult.value = null
  const p = { hive: hostRemoteReg.value.hive, key: hostRemoteReg.value.key }
  if (hostRemoteReg.value.value?.trim()) p.value = hostRemoteReg.value.value.trim()
  const done = await hostRemoteExec('reg_read', p)
  if (done?.ok) hostRemoteRegResult.value = done.result
}

async function hostRemoteRunCmd() {
  const cmd = hostRemoteCmdLine.value.trim()
  if (!cmd) return
  hostRemoteCmdLog.value.unshift({ at: fmtTime(new Date().toISOString()), cmd })
  hostRemoteCmdLog.value = hostRemoteCmdLog.value.slice(0, 40)
  const done = await hostRemoteExec('run_cmd', { command: cmd, timeout_sec: 90 })
  if (done?.ok) {
    hostRemoteCmdOut.value = done.result?.output || JSON.stringify(done.result, null, 2)
  }
}

async function hostRemoteShellStart() {
  hostRemoteShellHint.value = ''
  error.value = ''
  if (!isAdmin.value) {
    hostRemoteShellHintKind.value = 'err'
    hostRemoteShellHint.value = '需要管理员账号才能下发 Shell 指令'
    hostRemoteShellAppend('err', hostRemoteShellHint.value)
    return
  }
  if (!selected.value?.online) {
    hostRemoteShellHintKind.value = 'err'
    hostRemoteShellHint.value = '终端离线，无法连接'
    hostRemoteShellAppend('err', hostRemoteShellHint.value)
    return
  }
  hostRemoteShellLines.value = []
  hostRemoteShellId.value = ''
  hostRemoteShellPhase.value = 'connecting'
  hostRemoteShellAppend('sys', '正在连接终端 cmd 会话…')
  try {
    const done = await hostRemoteExec('shell_open', {}, { timeoutMs: 90000 })
    const sid = done?.result?.session_id || done?.result?.sessionId || ''
    if (done?.ok && sid) {
      hostRemoteShellId.value = String(sid)
      hostRemoteShellPhase.value = 'live'
      hostRemoteShellHintKind.value = 'ok'
      hostRemoteShellHint.value = 'Shell 已连接，可直接输入命令'
      hostRemoteShellAppend('sys', '已连接。输入命令后按 Enter；输出将自动刷新。')
      stopHostRemoteShellPoll()
      await hostRemoteShellPollOnce()
      hostRemoteShellPollTimer = setInterval(() => { hostRemoteShellPollOnce() }, 1500)
      nextTick(() => { hostRemoteShellInputRef.value?.focus() })
      return
    }
    hostRemoteShellPhase.value = 'error'
    const msg = done?.error || '连接失败：请确认 Agent 已重新编译部署、EDR 策略已开启「交互式 Shell」'
    hostRemoteShellHintKind.value = 'err'
    hostRemoteShellHint.value = msg
    hostRemoteShellAppend('err', msg)
  } catch (e) {
    hostRemoteShellPhase.value = 'error'
    const msg = e?.message || String(e)
    hostRemoteShellHintKind.value = 'err'
    hostRemoteShellHint.value = msg
    hostRemoteShellAppend('err', msg)
  }
}

async function hostRemoteShellPollOnce() {
  if (hostRemoteShellPollBusy || !hostRemoteShellId.value || !selected.value?.online) return
  hostRemoteShellPollBusy = true
  try {
    const done = await hostRemoteExec(
      'shell_poll',
      { session_id: hostRemoteShellId.value },
      { timeoutMs: 45000, busy: false, refreshCmdLog: false },
    )
    if (!done?.ok) {
      if (String(done?.error || '').includes('session not found')) {
        hostRemoteShellAppend('err', '会话已在终端结束，请重新连接')
        await hostRemoteShellStop(true)
      }
      return
    }
    const chunk = String(done.result?.output || '')
    if (chunk.trim()) hostRemoteShellAppend('out', chunk.trimEnd())
  } finally {
    hostRemoteShellPollBusy = false
  }
}

function hostRemoteShellClear() {
  hostRemoteShellLines.value = []
}

async function hostRemoteShellQuick(cmd) {
  if (!hostRemoteShellId.value) return
  hostRemoteShellInput.value = cmd
  await hostRemoteShellSend()
}

async function hostRemoteShellSend() {
  const line = hostRemoteShellInput.value.trim()
  if (!line || !hostRemoteShellId.value) return
  hostRemoteShellAppend('in', line)
  hostRemoteShellInput.value = ''
  const done = await hostRemoteExec(
    'shell_write',
    { session_id: hostRemoteShellId.value, input: line },
    { timeoutMs: 90000, busy: false, refreshCmdLog: true },
  )
  if (!done?.ok) {
    hostRemoteShellAppend('err', done?.error || '发送失败')
    return
  }
  await hostRemoteShellPollOnce()
  setTimeout(() => { hostRemoteShellPollOnce() }, 800)
}

async function hostRemoteShellStop(silent = false) {
  stopHostRemoteShellPoll()
  const sid = hostRemoteShellId.value
  hostRemoteShellId.value = ''
  if (sid) {
    await hostRemoteExec('shell_close', { session_id: sid }, { timeoutMs: 30000, busy: false, refreshCmdLog: true })
  }
  hostRemoteShellPhase.value = 'idle'
  if (!silent) hostRemoteShellAppend('sys', '会话已断开')
}

function startHostRemotePoll() {
  stopHostRemotePoll()
  hostRemotePollTimer = setInterval(async () => {
    if (page.value !== 'hosts' || hostTabGroup.value !== 'remote' || !selected.value?.agent_id) {
      stopHostRemotePoll()
      return
    }
    await loadHostRemoteCommands()
    const pending = hostRemoteCommands.value.some((c) => c.status === 'pending' || c.status === 'sent')
    if (!pending) stopHostRemotePoll()
  }, 2500)
}

async function loadHostRemoteCommands() {
  const aid = selected.value?.agent_id
  if (!aid) return
  try {
    const r = await listAgentCommands(aid)
    hostRemoteCommands.value = (r?.items || []).slice(0, 40)
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

function hostRemotePrefillFromRow(row) {
  if (!row) return
  if (row.pid != null && row.pid !== '') hostRemoteForm.value.pid = String(row.pid)
  if (row.pid != null && row.pid !== '') hostRemoteForm.value.scanPid = String(row.pid)
  const p = row.path || row.image || ''
  if (p) hostRemoteForm.value.path = String(p)
}

function hostRemoteFromRow(row) {
  hostRemotePrefillFromRow(row)
  selectHostGroup('remote')
}

function openInvestigateForHost() {
  const h = selected.value?.hostname || ''
  if (!h) return
  goMenu('investigate')
  invFilters.value = { ...invFilters.value, hostname: h }
  invQ.value = ''
  runInvestigate()
}

async function hostRemoteAction(action) {
  const a = selected.value
  if (!a?.agent_id) return
  if (!a.online) {
    error.value = '终端离线，无法下发远程指令'
    return
  }
  const params = {}
  if (action === 'kill_process') {
    const pid = Number(String(hostRemoteForm.value.pid || '').trim())
    if (!pid) {
      error.value = '请填写要结束的 PID'
      return
    }
    if (!window.confirm(`确认结束 ${a.hostname || a.agent_id} 上的进程 PID ${pid}？`)) return
    params.pid = pid
  } else if (action === 'quarantine_file') {
    const path = String(hostRemoteForm.value.path || '').trim()
    if (!path) {
      error.value = '请填写要隔离的文件路径'
      return
    }
    if (!window.confirm(`确认隔离文件？\n${path}`)) return
    params.path = path
  } else if (action === 'isolate_network') {
    if (!window.confirm('确认对该终端执行网络隔离？')) return
  } else if (action === 'unisolate_network') {
    if (!window.confirm('确认解除网络隔离？')) return
  } else if (action === 'scan_memory') {
    const sp = String(hostRemoteForm.value.scanPid || '').trim()
    const pid = sp ? Number(sp) : 0
    if (pid) params.pid = pid
    else params.max_processes = 40
    if (!window.confirm(pid ? `扫描 PID ${pid} 内存？` : '扫描该主机前 40 个进程内存？')) return
  } else if (action === 'refresh_modules') {
    if (!window.confirm('触发全模块快照刷新？下一心跳起立即采集。')) return
  }
  hostRemoteBusy.value = true
  try {
    await createAgentCommand(a.agent_id, action, params)
    okMsg.value = `${actionLabel(action)} · 指令已下发`
    await loadHostRemoteCommands()
    startHostRemotePoll()
  } catch (err) {
    error.value = err?.message || String(err)
  } finally {
    hostRemoteBusy.value = false
  }
}

async function loadRespCommands() {
  const aid = activeEvent.value?.agent_id
  if (!aid) return
  try {
    const r = await listAgentCommands(aid)
    respCommands.value = r?.items || []
    const latest = respCommands.value[0]
    if (!latest) return
    const key = `${latest.id}:${latest.status}`
    if (key === respToastCmdKey) return
    if (latest.status === 'done') {
      respToastCmdKey = key
      showRespToast('ok', `${actionLabel(latest.action)} · 成功`, friendlyCmdResult(latest.action, latest.result_json))
    } else if (latest.status === 'failed') {
      respToastCmdKey = key
      showRespToast('err', `${actionLabel(latest.action)} · 失败`, friendlyCmdResult(latest.action, latest.result_json), { ms: 6000 })
    } else if (latest.status === 'pending' || latest.status === 'sent') {
      respToastCmdKey = key
      showRespToast('wait', `${actionLabel(latest.action)} · ${cmdStatusLabel(latest.status)}`, '等待终端心跳执行…', { sticky: true })
    }
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

function startRespPoll() {
  if (respPollTimer) clearInterval(respPollTimer)
  respPollTimer = setInterval(async () => {
    if (page.value !== 'threat-view' || !activeEvent.value?.agent_id) return
    await loadRespCommands()
    const pending = respCommands.value.some((c) => c.status === 'pending' || c.status === 'sent')
    if (!pending && respPollTimer) {
      clearInterval(respPollTimer)
      respPollTimer = null
    }
  }, 2500)
}

function goAuditPage() {
  section.value = 'deploy'
  page.value = 'audit'
  loadAudit()
}

async function doResponse(action) {
  const e = activeEvent.value
  if (!e?.agent_id) return
  const ev = eventEvidence.value.evidence || {}
  const params = {}
  if (action === 'kill_process') {
    const pid = Number(ev.pid)
    if (!pid) {
      error.value = '证据中无 PID，无法结束进程'
      return
    }
    if (!window.confirm(`确认结束主机进程 PID ${pid}？`)) return
    params.pid = pid
    // 身份保护：终端会校验 PID 仍对应取证时的同一进程，避免 PID 复用误杀
    const guid = String(ev.process_guid || '').trim()
    if (guid) params.process_guid = guid
  } else if (action === 'quarantine_file') {
    const path = ev.path || evidencePath.value
    if (!path) {
      error.value = '证据中无文件路径'
      return
    }
    if (!window.confirm(`确认隔离文件？\n${path}`)) return
    params.path = path
    // 内容/实体保护：文件已被替换时终端拒绝隔离
    const sha = String(ev.sha256 || '').trim()
    if (/^[0-9a-fA-F]{64}$/.test(sha)) params.sha256 = sha.toLowerCase()
    const fid = String(ev.file_id || '').trim()
    if (fid) params.file_id = fid
  } else if (action === 'isolate_network') {
    if (!window.confirm('确认网络隔离该终端？（将阻断大部分出站，保留 DNS/管理端）')) return
  } else if (action === 'unisolate_network') {
    if (!window.confirm('确认解除网络隔离？')) return
  } else if (action === 'scan_memory') {
    const pid = Number(ev.pid)
    if (pid) params.pid = pid
    else params.max_processes = 40
    if (!window.confirm(pid ? `扫描进程 PID ${pid} 的内存？` : '未找到 PID，将扫描该主机前 40 个进程内存，继续？')) return
  }
  respBusy.value = true
  try {
    const r = await createAgentCommand(e.agent_id, action, params)
    threatTab.value = 'response'
    respToastCmdKey = ''
    showRespToast('wait', `${actionLabel(action)} · 已下发`, `指令 ${r?.id || ''} 等待终端执行…`, { sticky: true })
    await loadRespCommands()
    startRespPoll()
  } catch (err) {
    error.value = err?.message || String(err)
  } finally {
    respBusy.value = false
  }
}

function openTimelineFor(agentId) {
  section.value = 'detect'
  page.value = 'timeline'
  tlAgentId.value = agentId || ''
  loadTimeline()
}

/** 概览：外联 IP → 时间线；DNS → DNS 狩猎页 */
function openOverviewNetworkView(mode) {
  if (mode === 'dns') {
    goMenu('dns')
    return
  }
  section.value = 'detect'
  page.value = 'timeline'
  tlAgentId.value = ''
  tlTypeFilter.value = 'net'
  tlQ.value = '外联'
  loadTimeline()
}

function jumpThreatTimelineWindow() {
  const ev = activeEvent.value
  if (!ev?.agent_id) return
  tlAgentId.value = ev.agent_id
  const flat = evidenceFlat.value || {}
  tlQ.value = flat.pid != null && flat.pid !== '' ? String(flat.pid) : (flat.process_name || flat.name || '')
  section.value = 'detect'
  page.value = 'timeline'
  loadTimeline()
}

function huntFromEmptyCmd() {
  const ev = activeEvent.value
  const flat = evidenceFlat.value || {}
  const q = flat.pid != null && flat.pid !== '' ? String(flat.pid) : (flat.process_name || flat.name || ev?.title || '')
  openHuntModule('process', q)
}

async function loadTimeline() {
  try {
    const r = await listTimeline({ agentId: tlAgentId.value, q: tlQ.value, kind: tlTypeFilter.value, limit: 300 })
    timelineItems.value = r?.items || []
    timelineKinds.value = r?.kinds || {}
    timelineTotal.value = r?.total ?? timelineItems.value.length
    tlOpenId.value = null
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

function natureLabel(n) {
  return ({ threat: '威胁', risk: '风险', minor: '细微', surface: '攻击面' })[n] || n || '—'
}
function histMax() {
  let m = 1
  for (const b of invHist.value || []) m = Math.max(m, Number(b.total) || 0)
  return m
}
function histSegH(b, key) {
  const v = Number(b?.[key]) || 0
  const pct = Math.round((v / histMax()) * 100)
  return pct > 0 ? `${Math.max(pct, 3)}%` : '0'
}
function histTick(ts) {
  const s = String(ts || '')
  return s.length >= 16 ? s.slice(11, 16) : s.slice(5, 16)
}
function loadInvLocal() {
  try {
    invSaved.value = JSON.parse(localStorage.getItem('edr_inv_saved') || '[]') || []
    invHistory.value = JSON.parse(localStorage.getItem('edr_inv_hist') || '[]') || []
  } catch {
    invSaved.value = []
    invHistory.value = []
  }
}
function persistInvLocal() {
  localStorage.setItem('edr_inv_saved', JSON.stringify(invSaved.value.slice(0, 30)))
  localStorage.setItem('edr_inv_hist', JSON.stringify(invHistory.value.slice(0, 40)))
}
function saveInvQuery() {
  const name = window.prompt('保存名称', invQ.value || '未命名查询')
  if (!name) return
  invSaved.value.unshift({
    name,
    q: invQ.value,
    range: invRange.value,
    ...invFilters.value,
    natureTab: invNatureTab.value,
    hideProcNoise: invHideProcNoise.value,
  })
  persistInvLocal()
  invShowSaved.value = true
  flashOk('查询已保存')
}
function applyInvSaved(s) {
  if (!s) return
  invQ.value = s.q || ''
  invRange.value = s.range || 'today'
  invFilters.value = {
    nature: s.nature || '',
    etype: s.etype || '',
    hostname: s.hostname || '',
    path: s.path || '',
    hash_q: s.hash_q || '',
  }
  invNatureTab.value = s.natureTab || s.nature || ''
  if (s.hideProcNoise !== undefined) invHideProcNoise.value = !!s.hideProcNoise
  invShowSaved.value = false
  invShowHist.value = false
  runInvestigate()
}
function setInvNature(n) {
  invNatureTab.value = n || ''
  invFilters.value = { ...invFilters.value, nature: n || '' }
  runInvestigate()
}
function resetInvestigate() {
  invQ.value = ''
  invFilters.value = { nature: '', etype: '', hostname: '', path: '', hash_q: '', entity: '', tactic: '', os: '' }
  invNatureTab.value = ''
  invRange.value = 'today'
  invMoreFilters.value = false
  invHideProcNoise.value = true
  closeInvDetail()
  runInvestigate()
}
let invReqSeq = 0
let lastInvestigateAt = 0
async function runInvestigate() {
  const seq = ++invReqSeq
  invBusy.value = true
  try {
    const nature = invNatureTab.value || invFilters.value.nature || ''
    const r = await investigateLogs({
      q: invQ.value.trim(),
      range: invRange.value,
      nature,
      etype: invFilters.value.etype,
      hostname: invFilters.value.hostname,
      path: invFilters.value.path,
      hash_q: invFilters.value.hash_q,
      hide_proc_noise: invHideProcNoise.value ? 1 : 0,
      limit: 200,
    })
    if (seq !== invReqSeq) return
    let items = r?.items || []
    const ent = String(invFilters.value.entity || '').trim().toLowerCase()
    if (ent) {
      items = items.filter((it) => `${it.name || ''} ${it.path || ''} ${it.command_line || ''}`.toLowerCase().includes(ent))
    }
    if (invFilters.value.tactic) {
      items = items.filter((it) => guessAttck(it.summary || it.title, it.module).tactic === invFilters.value.tactic)
    }
    if (invFilters.value.os) {
      items = items.filter((it) => agentOsOf(it.agent_id) === invFilters.value.os)
    }
    invItems.value = items
    invPage.value = 1
    invCounts.value = r?.counts || { all: 0, threat: 0, risk: 0, minor: 0, surface: 0 }
    invHist.value = r?.histogram || []
    invFacets.value = r?.facets || { etype: [], hostname: [] }
    lastInvestigateAt = Date.now()
    const stamp = fmtTime(new Date().toISOString())
    invHistory.value.unshift({
      at: stamp,
      q: invQ.value,
      range: invRange.value,
      ...invFilters.value,
      natureTab: invNatureTab.value,
      hideProcNoise: invHideProcNoise.value,
    })
    invHistory.value = invHistory.value.slice(0, 40)
    persistInvLocal()
  } catch (e) {
    if (seq === invReqSeq) error.value = e?.message || String(e)
  } finally {
    if (seq === invReqSeq) invBusy.value = false
  }
}
async function openInvDetail(id) {
  if (!id) return
  invDetailId.value = id
  invDetailTab.value = 'info'
  try {
    const r = await investigateLogDetail(id)
    invDetail.value = r
  } catch (e) {
    error.value = e?.message || String(e)
    invDetail.value = null
  }
}
function closeInvDetail() {
  invDetail.value = null
  invDetailId.value = null
  entityView.value = null
}

// ---- 策略版本 / 生效情况 ----
const POLICY_STATUS_LABELS = {
  applied: '已生效', probation: '试用中', rejected: '已拒绝', rolled_back: '已回滚', none: '未下发',
}
const policyHistory = ref([])
const policyRollout = ref(null)
async function loadPolicyMeta() {
  try {
    const [h, r] = await Promise.all([getPolicyHistory('global'), getPolicyRollout('global')])
    policyHistory.value = h?.items || []
    policyRollout.value = r || null
  } catch { /* 旧服务端无此接口 */ }
}
async function doPolicyRollback(rev) {
  if (!window.confirm(`以 rev ${rev} 的内容发布新版本？终端会在下次心跳原子生效。`)) return
  try {
    const r = await rollbackPolicy(rev, 'global')
    okMsg.value = `已回滚：发布为 rev ${r?.rev}`
    setTimeout(() => { okMsg.value = '' }, 2500)
    await loadPolicyPage()
  } catch (e) { error.value = e?.message || String(e) }
}

// ---- DNS 狩猎 ----
const dnsItems = ref([])
const dnsQ = ref('')
const dnsDomainQ = ref('')
const dnsIpQ = ref('')
const dnsProcQ = ref('')
const dnsAgent = ref('')
const dnsGroupId = ref('')
const dnsNx = ref(false)
const dnsDgaOnly = ref(false)
const dnsIntelOnly = ref(false)
const dnsBusy = ref(false)
const dnsPage = ref(1)
const dnsPageSize = ref(20)
const dnsSort = ref({ key: 'hits', dir: 'desc' })
const dnsFiltersOn = ref({
  domain: '', ip: '', proc: '', group: '', nx: false, dga: false, intel: false, agent: '',
})

const dnsIocMeta = ref({ lib: 'ioc_data', path: '', ok: null, matched: 0, hint: '' })

const dnsHasFilter = computed(() => {
  const on = dnsFiltersOn.value || {}
  return Boolean(on.domain || on.ip || on.proc || on.group || on.nx || on.dga || on.intel || on.agent)
})

const filteredDnsItems = computed(() => {
  const on = dnsFiltersOn.value || {}
  let list = [...(dnsItems.value || [])]
  if (on.group) {
    const g = (groupItems.value || []).find((x) => String(x.id) === String(on.group))
    const ids = new Set((g?.agent_ids || []).map(String))
    list = ids.size ? list.filter((d) => ids.has(String(d.agent_id))) : []
  }
  if (on.domain) {
    const q = on.domain
    list = list.filter((d) => String(d.domain || '').toLowerCase().includes(q))
  }
  if (on.ip) {
    const q = on.ip
    list = list.filter((d) => (d.answers || []).some((a) => String(a).toLowerCase().includes(q)))
  }
  if (on.proc) {
    const q = on.proc
    list = list.filter((d) => (d.processes || []).some((p) => String(p).toLowerCase().includes(q)))
  }
  if (on.nx) list = list.filter((d) => Number(d.nx_hits || 0) > 0)
  if (on.dga) list = list.filter((d) => Number(d.max_dga || 0) >= 0.7)
  if (on.intel) list = list.filter((d) => d.ioc_hit)
  const { key, dir } = dnsSort.value
  list.sort((a, b) => {
    let av = a[key]
    let bv = b[key]
    if (key === 'hits' || key === 'nx_hits' || key === 'max_dga') {
      av = Number(av) || 0
      bv = Number(bv) || 0
    } else if (key === 'ioc_hit') {
      av = a.ioc_hit ? 1 : 0
      bv = b.ioc_hit ? 1 : 0
    } else {
      av = av == null ? '' : String(av)
      bv = bv == null ? '' : String(bv)
    }
    if (av === bv) return String(a.domain || '').localeCompare(String(b.domain || ''))
    const cmp = av > bv ? 1 : -1
    return dir === 'asc' ? cmp : -cmp
  })
  return list
})

const dnsStats = computed(() => {
  const list = filteredDnsItems.value
  return {
    total: list.length,
    hits: list.reduce((s, d) => s + (Number(d.hits) || 0), 0),
    nx: list.filter((d) => Number(d.nx_hits) > 0).length,
    intel: list.filter((d) => d.ioc_hit).length,
  }
})

function dnsIocLabel(d) {
  const h = (d?.ioc_hits || [])[0]
  const fam = String(h?.malware || '').split(',')[0].trim()
  if (fam) return fam.length > 12 ? `${fam.slice(0, 12)}…` : fam
  return '情报'
}
function dnsIocTitle(d) {
  const rows = d?.ioc_hits || []
  if (!rows.length) return '命中 ioc_data.db（精确）'
  return rows.map((h) => {
    const fam = h.malware ? ` · ${h.malware}` : ''
    const src = h.source ? ` @${h.source}` : ''
    return `${h.type || 'ioc'}=${h.matched || ''}${fam}${src}`
  }).join('\n')
}

const dnsPageCount = computed(() => Math.max(1, Math.ceil((filteredDnsItems.value || []).length / dnsPageSize.value)))
const pagedDnsItems = computed(() => {
  const start = (dnsPage.value - 1) * dnsPageSize.value
  return filteredDnsItems.value.slice(start, start + dnsPageSize.value)
})
watch([filteredDnsItems, dnsPageSize], () => {
  if (dnsPage.value > dnsPageCount.value) dnsPage.value = dnsPageCount.value
})
watch([() => dnsSort.value.key, () => dnsSort.value.dir, () => dnsFiltersOn.value], () => {
  dnsPage.value = 1
})

function toggleDnsSort(key) {
  if (dnsSort.value.key === key) {
    dnsSort.value = { key, dir: dnsSort.value.dir === 'asc' ? 'desc' : 'asc' }
  } else {
    dnsSort.value = { key, dir: key === 'domain' ? 'asc' : 'desc' }
  }
}
function dnsSortMark(key) {
  if (dnsSort.value.key !== key) return '↕'
  return dnsSort.value.dir === 'asc' ? '↑' : '↓'
}
function applyDnsFilters() {
  const prev = dnsFiltersOn.value || {}
  const next = {
    domain: dnsDomainQ.value.trim().toLowerCase(),
    ip: dnsIpQ.value.trim().toLowerCase(),
    proc: dnsProcQ.value.trim().toLowerCase(),
    group: dnsGroupId.value || '',
    nx: !!dnsNx.value,
    dga: !!dnsDgaOnly.value,
    intel: !!dnsIntelOnly.value,
    agent: dnsAgent.value || '',
  }
  // 分组 / DGA / 情报 仅前端滤；终端与关键词变化才回源
  const needReload = !dnsItems.value.length
    || prev.agent !== next.agent
    || prev.nx !== next.nx
    || prev.domain !== next.domain
    || prev.ip !== next.ip
    || prev.proc !== next.proc
  dnsFiltersOn.value = next
  if (needReload) loadDns()
  else dnsPage.value = 1
}
function resetDnsFilters() {
  dnsDomainQ.value = ''
  dnsIpQ.value = ''
  dnsProcQ.value = ''
  dnsQ.value = ''
  dnsAgent.value = ''
  dnsGroupId.value = ''
  dnsNx.value = false
  dnsDgaOnly.value = false
  dnsIntelOnly.value = false
  dnsFiltersOn.value = {
    domain: '', ip: '', proc: '', group: '', nx: false, dga: false, intel: false, agent: '',
  }
  loadDns()
}
async function loadDns() {
  dnsBusy.value = true
  try {
    if (!agents.value.length) {
      try {
        const list = await listAgents(45)
        agents.value = list?.items || []
      } catch { /* ignore */ }
    }
    // 服务端用组合关键词预筛，细项在客户端再滤
    const q = [
      dnsFiltersOn.value.domain || dnsDomainQ.value.trim(),
      dnsFiltersOn.value.ip || dnsIpQ.value.trim(),
      dnsFiltersOn.value.proc || dnsProcQ.value.trim(),
      dnsQ.value.trim(),
    ].filter(Boolean)[0] || ''
    const agentId = dnsFiltersOn.value.agent || dnsAgent.value
    const nxOnly = !!(dnsFiltersOn.value.nx || dnsNx.value)
    const r = await huntDns({ q, agentId, nxOnly, limit: 800, matchIoc: true })
    dnsItems.value = r?.items || []
    dnsIocMeta.value = r?.ioc || { lib: 'ioc_data', path: '', ok: null, matched: 0, hint: '' }
    dnsPage.value = 1
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    dnsBusy.value = false
  }
}
/** 点次数 → 日志调查 */
function openDnsLogHits(d) {
  if (!d) return
  invQ.value = String(d.domain || (d.answers || [])[0] || '').trim()
  invRange.value = '7d'
  invFilters.value = {
    nature: '', etype: '', hostname: d.hostname || '',
    path: '', hash_q: '', entity: '', tactic: '', os: '',
  }
  invNatureTab.value = ''
  lastInvestigateAt = 0
  goMenu('investigate')
  runInvestigate()
}
/** 点行 / 域名 → 威胁事件按情报 IP/域名筛选 */
function openDnsThreat(d) {
  if (!d) return
  const ioc = String(d.domain || (d.answers || [])[0] || '').trim()
  section.value = 'detect'
  page.value = 'events'
  eventListReturnPage.value = 'events'
  resetEventFilters()
  eventIocQ.value = ioc
  eventTypeFilter.value = ''
  applyEventFilters()
  loadEvents(false)
}

// ---- 进程实体（boot_id + pid + 创建时间；退出后保留墓碑） ----
const entityView = ref(null)
const entityBusy = ref(false)
const entityErr = ref('')
const invEntityId = computed(() => {
  const it = invDetail.value?.item || {}
  const raw = invDetail.value?.raw
  const d = (raw && typeof raw === 'object' && (raw.detail || raw)) || parseJsonSafe(it.detail_json)
  return String(d?.entity_id || it.entity_id || '')
})
async function loadEntity(entityId) {
  const aid = invDetail.value?.item?.agent_id
  if (!aid || !entityId) return
  entityBusy.value = true
  entityErr.value = ''
  try {
    entityView.value = await getProcessEntity(aid, entityId)
  } catch (e) {
    entityView.value = null
    entityErr.value = e?.message || String(e)
  } finally {
    entityBusy.value = false
  }
}
function openEntityTab() {
  invDetailTab.value = 'entity'
  loadEntity(invEntityId.value)
}
function entityFieldsOf(e) {
  if (!e) return []
  const rows = [
    ['实体 ID', e.entity_id], ['PID / 父 PID', `${e.pid ?? '—'} / ${e.ppid ?? '—'}`], ['路径', e.path],
    ['命令行', e.command_line], ['用户', e.user], ['完整性', e.integrity], ['创建时间', e.create_time],
    ['退出时间', e.exit_time], ['退出码', e.exit_code], ['开机标识', e.boot_id], ['来源', e.source],
  ]
  return rows.filter(([, v]) => v !== '' && v != null).map(([k, v]) => ({ k, v }))
}
function jumpInvTimeline() {
  const it = invDetail.value?.item || {}
  const aid = it.agent_id
  if (!aid) {
    error.value = '该日志缺少终端 ID，无法打开时间线'
    return
  }
  closeInvDetail()
  openTimelineFor(aid)
}
function jumpInvHost() {
  const it = invDetail.value?.item || {}
  const aid = it.agent_id
  if (!aid) {
    error.value = '该日志缺少终端 ID，无法打开主机'
    return
  }
  let a = agents.value.find((x) => x.agent_id === aid)
  if (!a && it.hostname) {
    a = agents.value.find((x) => String(x.hostname || '').toLowerCase() === String(it.hostname).toLowerCase())
  }
  if (!a) {
    a = {
      agent_id: aid,
      hostname: it.hostname || aid,
      ip: '',
      online: false,
      last_seen: '',
      version: '',
    }
  }
  closeInvDetail()
  openHost(a, 'hosts')
}

function etypeKind(etype) {
  const e = String(etype || '').toLowerCase()
  if (e.includes('remote_thread') || e.includes('protect_block') || e.includes('driver')) return 'alert'
  if (e.includes('image_load')) return 'module'
  if (e.includes('scriptblock') || e.startsWith('win_ps')) return 'script'
  if (e.includes('file') || e.startsWith('fim_')) return 'file'
  if (e.includes('exit')) return 'exit'
  if (e.includes('dns') || e.includes('network')) return 'net'
  if (['persist', 'registry', 'service', 'task', 'account', 'logon', 'group', 'audit', 'priv'].some((k) => e.includes(k))) return 'persist'
  if (e.includes('process') || e.includes('live') || e.includes('thread') || e.includes('access')) return 'proc'
  return 'other'
}
function etypeLabel(etype) {
  const map = {
    process_create: '进程创建',
    process_create_live: '进程创建(WMI)',
    process_create_etw: '进程创建(ETW)',
    process_create_kernel: '进程创建(内核)',
    process_exit: '进程退出',
    process_exit_kernel: '进程退出(内核)',
    process_exit_etw: '进程退出(ETW)',
    dns_summary: 'DNS 汇总',
    dns_nx_burst: 'DNS 解析失败爆发',
    registry_set: '注册表安全项变更',
    registry_delete: '注册表安全项删除',
    fim_add: 'FIM 新增',
    fim_modify: 'FIM 修改',
    fim_delete: 'FIM 删除',
    fim_rename: 'FIM 重命名',
    fim_overflow: 'FIM 变更过多',
    process_access: '进程打开',
    remote_thread: '远程线程',
    file_create: '文件创建',
    file_write: '文件更新',
    file_write_etw: '文件落地(ETW)',
    network: '网络连接',
    network_connect: '网络外联',
    network_connect_etw: '网络外联(ETW)',
    dns_query: 'DNS 查询',
    registry_write: '注册表写入',
    persist_add: '持久化新增',
    persist_modify: '持久化修改',
    persist_delete: '持久化删除',
    win_logon: '登录成功',
    win_logon_fail: '登录失败',
    win_explicit_logon: '显式凭据',
    win_account_create: '账号创建',
    win_account_enable: '账号启用',
    win_password_reset: '密码重置',
    win_group_add: '加入用户组',
    win_service_install: '服务安装',
    win_task_create: '计划任务创建',
    win_task_update: '计划任务更新',
    win_audit_clear: '清空安全日志',
    image_load_etw: 'DLL 加载(ETW)',
    image_load_kernel: 'DLL 加载(内核)',
    driver_load_kernel: '驱动加载(内核)',
    remote_thread_kernel: '远程线程注入',
    protect_block_kernel: '自保护拦截',
    sensor_status: '传感器状态',
    etw_status: 'ETW 状态',
    winevent_status: '事件通道状态',
  }
  return map[etype] || etype || '事件'
}
const DETAIL_LABELS = {
  name: '名称', path: '路径', pid: 'PID', ppid: '父PID', parent_name: '父进程',
  parent_path: '父路径', command_line: '命令行', user: '用户', signed: '签名', signer: '签名者',
  sha256: 'SHA256', size: '大小', size_kb: '大小KB', ext: '扩展名',
  modified: '修改时间', created: '创建时间', directory: '目录', location: '扫描根目录',
  process_name: '关联进程', source: '采集来源', remote: '远端', local: '本地', proto: '协议',
  daddr: '目标 IP', dport: '目标端口', saddr: '源 IP', sport: '源端口',
  image: '映像', target_pid: '目标 PID', company: '公司名', file_version: '文件版本',
  module: '模块', module_name: '模块名', host_process: '宿主进程', process_path: '进程路径',
  entity_id: '进程实体', parent_entity_id: '父进程实体', boot_id: '开机标识', exit_code: '退出码',
  duration_sec: '存活秒数', query: '查询域名', qtype_name: '记录类型', status_name: '解析结果',
  answers: '应答 IP', cnames: 'CNAME', dga_score: 'DGA 评分', domain: '域名',
  reg_key: '注册表键', value_name: '值名', value: '值', old_value: '旧值', value_type: '值类型',
  category: '类别', label: '监控点', old_sha256: '旧 SHA256', old_path: '原路径', offline: '离线期间',
  root: '监控根目录', mtime: '修改时间',
}
function techChip(id, label) {
  const tid = String(id || '').trim()
  if (!tid) return ''
  const lab = String(label || '').trim()
  if (!lab || lab === tid) return tid
  return `${tid} · ${lab}`
}
function tlPid(t) {
  const d = parseTlDetail(t)
  const v = d?.pid ?? d?.target_pid
  return v == null || v === '' ? '' : String(v)
}
function openTimelineHostPid(t) {
  const a = agents.value.find((x) => x.agent_id === t.agent_id)
  const pid = tlPid(t)
  if (a) {
    module.value = 'process'
    openHost(a, 'hosts')
    if (pid) {
      snapQ.value = pid
      setTimeout(() => {
        const hit = (snap.value?.items || []).find((r) => String(r.pid) === pid)
        if (hit) snapRow.value = hit
      }, 600)
    }
  } else goMenu('hosts')
}
function detailEntries(t) {
  const d = parseTlDetail(t)
  if (!d) return []
  const prefer = [
    'name', 'module', 'module_name', 'pid', 'ppid', 'parent_name', 'parent_path',
    'path', 'image', 'command_line', 'user', 'host_process', 'process_name',
    'signed', 'signer', 'sha256', 'company', 'file_version', 'ext', 'size', 'size_kb',
    'modified', 'created', 'directory', 'location',
    'remote', 'local', 'proto', 'daddr', 'dport', 'source',
  ]
  const keys = [
    ...prefer.filter((k) => d[k] != null && d[k] !== ''),
    ...Object.keys(d).filter((k) => !prefer.includes(k) && d[k] != null && d[k] !== '' && typeof d[k] !== 'object'),
  ]
  return keys.map((k) => ({
    k: DETAIL_LABELS[k] || colLabel(k) || k,
    key: k,
    v: String(d[k]),
    mono: ['path', 'parent_path', 'command_line', 'sha256', 'signer', 'remote', 'local', 'directory'].includes(k),
    wide: ['command_line', 'path', 'parent_path', 'sha256', 'signer'].includes(k),
  }))
}
function parseTlDetail(t) {
  let d = t?.detail
  if (typeof d === 'string') {
    try { d = JSON.parse(d) } catch { return null }
  }
  if (!d || typeof d !== 'object' || Array.isArray(d)) return null
  return d
}
function detailGroupsTl(t) {
  const rows = detailEntries(t)
  if (!rows.length) return []
  const groups = [
    { title: '进程', keys: ['name', 'pid', 'ppid', 'process_guid', 'parent_guid', 'parent_name', 'user', 'target_pid', 'process_name', 'host_process', 'create_time', 'elevated', 'integrity'] },
    { title: '模块 / 路径', keys: ['module', 'module_name', 'path', 'parent_path', 'command_line', 'image', 'directory', 'location', 'script_block', 'payload', 'process_path'] },
    { title: '签名 / 哈希', keys: ['signed', 'signer', 'sha256', 'company', 'file_version', 'ext', 'size', 'size_kb', 'created', 'modified'] },
    { title: '网络', keys: ['remote', 'local', 'proto', 'daddr', 'dport', 'saddr', 'sport'] },
    { title: '其他', keys: [] },
  ]
  const used = new Set()
  const out = []
  for (const g of groups.slice(0, 4)) {
    const items = rows.filter((r) => g.keys.includes(r.key))
    items.forEach((r) => used.add(r.key))
    if (items.length) out.push({ title: g.title, items })
  }
  const rest = rows.filter((r) => !used.has(r.key))
  const meta = [
    { k: '事件类型', key: '_etype', v: etypeLabel(t.etype), mono: false, wide: false },
    { k: '级别', key: '_sev', v: sevLabel(t.severity), mono: false, wide: false },
    { k: '主机', key: '_host', v: t.hostname || short(t.agent_id), mono: false, wide: false },
    { k: '时间', key: '_ts', v: fmtTime(t.ts || t.created_at), mono: false, wide: false },
  ]
  if (rest.length) out.push({ title: '其他字段', items: rest })
  out.unshift({ title: '事件信息', items: meta })
  return out
}
function detailPreview(t) {
  const rows = detailEntries(t)
  const want = ['名称', '模块', 'PID', '进程名', '用户', '父进程', '路径', '命令行', '签名', '签名者', '公司', 'SHA256', '远端', '扩展名', '目录', '大小KB', '创建时间', '修改时间']
  return rows.filter((r) => want.includes(r.k)).slice(0, 8).map((r) => ({
    k: r.k,
    v: r.v.length > 56 ? `${r.v.slice(0, 56)}…` : r.v,
  }))
}
function storyDetailPreview(n) {
  return detailPreview({ detail: n?.detail }).slice(0, 3)
}
function openTimelineHost(t) {
  const a = agents.value.find((x) => x.agent_id === t.agent_id)
  if (a) openHost(a, 'hosts')
  else goMenu('hosts')
}
function openTimelineThreats(t) {
  section.value = 'detect'
  page.value = 'events'
  focusKey.value = ''
  eventSevFilter.value = ''
  eventAgentId.value = t.agent_id || ''
  loadEvents(true, true)
}
const filteredTimeline = computed(() => {
  let list = timelineItems.value || []
  if (tlTypeFilter.value) {
    list = list.filter((t) => etypeKind(t.etype) === tlTypeFilter.value)
  }
  return list
})
const tlPage = ref(1)
const tlPageSize = ref(20)
const tlPageCount = computed(() => Math.max(1, Math.ceil(filteredTimeline.value.length / tlPageSize.value)))
const pagedTimeline = computed(() => {
  const start = (tlPage.value - 1) * tlPageSize.value
  return filteredTimeline.value.slice(start, start + tlPageSize.value)
})
watch(() => tlTypeFilter.value, () => {
  tlPage.value = 1
  if (page.value === 'timeline') loadTimeline()
})
watch(filteredTimeline, () => {
  if (tlPage.value > tlPageCount.value) tlPage.value = tlPageCount.value
})

const invPage = ref(1)
const invPageSize = ref(20)
const invPageCount = computed(() => Math.max(1, Math.ceil((invItems.value || []).length / invPageSize.value)))
const pagedInvItems = computed(() => {
  const start = (invPage.value - 1) * invPageSize.value
  return (invItems.value || []).slice(start, start + invPageSize.value)
})
watch(invItems, () => {
  if (invPage.value > invPageCount.value) invPage.value = invPageCount.value
})

const tlTypeOptions = computed(() => {
  const c = timelineKinds.value || {}
  return [
    { key: 'proc', label: '进程创建', count: c.proc || 0 },
    { key: 'exit', label: '进程退出', count: c.exit || 0 },
    { key: 'file', label: '文件创建/落地', count: c.file || 0 },
    { key: 'net', label: '网络 / DNS', count: c.net || 0 },
    { key: 'module', label: '模块加载', count: c.module || 0 },
    { key: 'script', label: '脚本', count: c.script || 0 },
    { key: 'persist', label: '注册表 / 持久化', count: c.persist || 0 },
    { key: 'alert', label: '告警类', count: c.alert || 0 },
  ]
})

async function runHunt() {
  const q = huntQ.value.trim()
  if (q.length < 2) {
    error.value = '请输入至少 2 个字符'
    return
  }
  huntBusy.value = true
  huntDone.value = false
  try {
    const r = await huntAgents(q, 120)
    huntHits.value = r?.items || []
    huntDone.value = true
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    huntBusy.value = false
  }
}

function openHuntHit(h) {
  if (h?.source === 'event' && h.id) {
    openEvent({ id: h.id, agent_id: h.agent_id, title: h.title, module: h.module, severity: h.severity })
    return
  }
  const a = agents.value.find((x) => x.agent_id === h.agent_id)
  if (a && h.module && LABELS[h.module]) {
    module.value = h.module
    openHost(a, 'hosts')
  } else if (h?.agent_id) {
    openTimelineFor(h.agent_id)
  }
}

async function loadPolicyPage() {
  try {
    const p = await getAgentPolicy('global')
    if (p?.policy) {
      policyForm.value = {
        heartbeat_sec: p.policy.heartbeat_sec ?? 5,
        response_enabled: p.policy.response_enabled !== false,
        timeline_process: p.policy.timeline_process !== false,
        timeline_file: p.policy.timeline_file !== false,
        timeline_network: p.policy.timeline_network !== false,
        self_protect: !!p.policy.self_protect,
        fim_enabled: p.policy.fim_enabled !== false,
        fim_paths_text: (p.policy.fim_paths || []).join('\n'),
        log_tail_paths_text: (p.policy.log_tail_paths || []).join('\n'),
        winevent_channel_mode: p.policy.winevent_channel_mode || 'all',
        winevent_channels_text: (p.policy.winevent_channels || []).join('\n'),
        timeline_retain_days: p.policy.timeline_retain_days ?? 14,
        events_retain_days: p.policy.events_retain_days ?? 90,
        mysql_dual_write: p.policy.mysql_dual_write !== false,
        intervals_sec: {
          process: p.policy.intervals_sec?.process ?? 5,
          network: p.policy.intervals_sec?.network ?? 5,
          file: p.policy.intervals_sec?.file ?? 12,
        },
        remote_ops_enabled: p.policy.remote_ops_enabled !== false,
        remote_ops_read_only: !!p.policy.remote_ops?.read_only,
        remote_ops_run_cmd: p.policy.remote_ops?.run_cmd_enabled !== false,
        remote_ops_shell: p.policy.remote_ops?.shell_enabled !== false,
      }
      policyRev.value = p.rev || 0
    }
    await loadWhitelistOnly()
    loadPolicyMeta()
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

async function loadIoc() {
  try {
    const [r, st] = await Promise.all([listIoc(), iocLibStatus().catch(() => null)])
    iocItems.value = r?.items || []
    if (st?.ok) {
      iocLib.value = st.lib || {}
      iocLibLocal.value = st.local_enabled || 0
    }
  } catch (e) { error.value = e?.message || String(e) }
}

function renderAiMarkdown(src) {
  const raw = String(src || '')
  if (!raw.trim()) return '<p class="muted">暂无正文</p>'
  const esc = raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
  const lines = esc.split(/\r?\n/)
  const html = []
  let inUl = false
  const closeUl = () => { if (inUl) { html.push('</ul>'); inUl = false } }
  for (const line of lines) {
    const h = /^(#{1,3})\s+(.+)$/.exec(line)
    if (h) {
      closeUl()
      const lv = h[1].length
      html.push(`<h${lv}>${h[2]}</h${lv}>`)
      continue
    }
    if (/^\s*[-*]\s+/.test(line)) {
      if (!inUl) { html.push('<ul>'); inUl = true }
      html.push(`<li>${line.replace(/^\s*[-*]\s+/, '')}</li>`)
      continue
    }
    closeUl()
    if (!line.trim()) {
      html.push('')
      continue
    }
    const inline = line
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    html.push(`<p>${inline}</p>`)
  }
  closeUl()
  return html.join('\n').replace(
    /(<li>)(.*?)(<\/li>)/g,
    (_, a, b, c) => a + b.replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>') + c,
  )
}

function seedAiHostsFromCache() {
  /** 进入页面立刻显示已有终端，避免空白等待 */
  if ((aiHosts.value || []).length) return
  const src = (agents.value || []).length ? agents.value : []
  if (!src.length) return
  aiHosts.value = src.map((a) => ({
    agent_id: a.agent_id,
    hostname: a.hostname || '',
    ip: a.ip || a.last_ip || '',
    last_ip: a.last_ip || '',
    online: !!a.online,
    status: a.status || '',
    os: a.os || a.platform || '',
    platform: a.platform || '',
    version: a.version || '',
    last_seen: a.last_seen || '',
    group: a.group || '',
    threat_count: 0,
    open_threat_count: 0,
  }))
}

async function refreshAiHostsOnly() {
  if (aiHostsInflight) return aiHostsInflight
  aiHostsLoading.value = true
  aiHostsInflight = (async () => {
    try {
      const hosts = await aiListHosts(120)
      if (hosts?.items) aiHosts.value = hosts.items
      return hosts
    } finally {
      aiHostsLoading.value = false
      aiHostsInflight = null
    }
  })()
  return aiHostsInflight
}

function stopAiHostsPoll() {
  if (aiHostsTimer) {
    clearInterval(aiHostsTimer)
    aiHostsTimer = null
  }
}

function startAiHostsPoll() {
  stopAiHostsPoll()
  aiHostsTimer = setInterval(() => {
    if (page.value !== 'ai-analyze') {
      stopAiHostsPoll()
      return
    }
    if (aiBusy.value || aiRefining.value) return
    refreshAiHostsOnly().catch(() => {})
  }, 15000)
}

async function loadAiAnalyzePage(opts = {}) {
  const force = opts?.force === true
  // 1) 先用缓存终端立刻铺列表，不再整页 aiBusy 卡住
  seedAiHostsFromCache()
  startAiHostsPoll()

  // 若全局 agents 也空，先快速拉一次 listAgents
  if (!(aiHosts.value || []).length && !(agents.value || []).length) {
    try {
      const list = await listAgents(120)
      agents.value = list?.items || list || []
      seedAiHostsFromCache()
    } catch (_) { /* ignore */ }
  }

  // 2) 主机列表优先刷新（带威胁数）
  const hostsTask = refreshAiHostsOnly().catch((e) => {
    if (!(aiHosts.value || []).length) error.value = e?.message || String(e)
  })

  // 3) 状态 / Skill 后台加载，不挡终端点击
  const sideTask = (async () => {
    try {
      const needSkills = force || !(aiSkills.value || []).length
      const [st, skills] = await Promise.all([
        aiStatus().catch(() => ({})),
        needSkills ? aiListSkills({ limit: 240, edrOnly: true }).catch(() => null) : Promise.resolve(null),
      ])
      if (st) {
        aiStatusInfo.value = {
          ...(aiStatusInfo.value || {}),
          ...st,
        }
      }
      if (skills?.items) {
        aiSkills.value = skills.items
        aiSkillsMeta.value = {
          total_indexed: skills.total_indexed || 0,
          edr_relevant: skills.edr_relevant || 0,
          returned: skills.returned || skills.items.length,
        }
      }
      if (isAdmin.value && st && !st.configured) {
        await setupLocalAiModel(true)
      }
    } catch (e) {
      // 侧栏失败不阻断主机列表
      if (!(aiHosts.value || []).length) error.value = e?.message || String(e)
    }
  })()

  await Promise.all([hostsTask, sideTask])
}

async function setupLocalAiModel(silent = false) {
  const quiet = silent === true
  try {
    aiBusy.value = true
    const r = await aiSetupLocal({
      base_url: 'http://192.168.31.220:8085/v1',
      api_key: 'strata-c0938a1a4b224201931e41d162698fe9',
      model: 'qwen3.8-flash-next-iq3_s',
      timeout: 120,
    })
    aiStatusInfo.value = {
      ...(aiStatusInfo.value || {}),
      configured: true,
      base_url: r?.platform?.base_url || 'http://192.168.31.220:8085/v1',
      model: r?.platform?.model || 'qwen3.8-flash-next-iq3_s',
      source: 'platform',
      timeout: 120,
      skills_root: aiStatusInfo.value?.skills_root,
    }
    if (!quiet) okMsg.value = '本地模型已同步到平台与当前账号'
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    aiBusy.value = false
  }
}

async function runAiAnalyze(host) {
  if (!host?.agent_id || aiBusy.value || aiRefining.value) return
  const aid = host.agent_id
  aiSelectedId.value = aid
    aiResult.value = null
    aiErrorText.value = ''
    aiRefining.value = false
    aiThinkIdx.value = 0
    aiEntityIdx.value = 0
    aiThreatIdx.value = 0
    aiLogIdx.value = 0
    aiLogCat.value = ''
    aiChainNodeId.value = ''
    aiTab.value = 'overview'
    aiBusy.value = true
    try {
    // 1) Agent Team 启发式（通常 <1s）
    const quick = await aiAnalyzeHost(aid, { useLlm: false })
    if (aiSelectedId.value !== aid) return
    aiResult.value = quick
    aiThinkIdx.value = 0
    aiEntityIdx.value = 0
    aiThreatIdx.value = 0
    aiLogIdx.value = 0
    aiLogCat.value = ''
    const nodes = quick?.result?.attack_graph?.nodes || []
    aiChainNodeId.value = (nodes.find((n) => n.type === 'stage') || nodes[0] || {}).id || ''
    // 优先看攻击链路；否则研判事件 / 日志
    const chainN = quick?.result?.attack_graph?.stage_count || 0
    const thrN = (quick?.result?.threat_events || []).length
    const logsN = (quick?.result?.forensics_logs || quick?.result?.security_logs || []).length
    if (chainN) aiTab.value = 'chain'
    else if (thrN) aiTab.value = 'threats'
    else if (logsN) aiTab.value = 'logs'
    else aiTab.value = 'overview'
    aiBusy.value = false
    // 2) 报告 Agent + 本地大模型精炼
    aiRefining.value = true
    try {
      const full = await aiAnalyzeHost(aid, { useLlm: true })
      if (aiSelectedId.value !== aid) return
      if (full?.ok) {
        aiResult.value = full
        if (full.error) aiErrorText.value = ''
      } else if (full?.error) {
        error.value = `模型精炼失败：${full.error}`
      }
    } catch (e) {
      if (aiSelectedId.value === aid) {
        error.value = `模型精炼失败：${e?.message || e}`
      }
    } finally {
      if (aiSelectedId.value === aid) aiRefining.value = false
    }
  } catch (e) {
    const msg = e?.message || String(e)
    aiErrorText.value = msg
    error.value = msg
    aiBusy.value = false
    aiRefining.value = false
  }
}

async function runAiDisposition(d) {
  const aid = aiSelectedId.value
  if (!aid || !d?.action || d.action === 'review') return
  const params = { ...(d.params || {}) }
  if (d.action === 'kill_process') {
    const pid = Number(params.pid)
    if (!pid) {
      error.value = '处置建议缺少 PID，无法结束进程'
      return
    }
    if (!window.confirm(`【人工审核】确认结束进程？\n${d.target || pid}\n原因：${d.reason || ''}`)) return
    params.pid = pid
  } else if (d.action === 'quarantine_file') {
    const path = params.path || d.target
    if (!path) {
      error.value = '处置建议缺少文件路径'
      return
    }
    if (!window.confirm(`【人工审核】确认隔离文件？\n${path}\n原因：${d.reason || ''}`)) return
    params.path = path
  } else if (d.action === 'isolate_network') {
    if (!window.confirm(`【人工审核】确认网络隔离该终端？\n${d.target || aid}\n将阻断大部分出站，保留 DNS/管理端。`)) return
  } else {
    error.value = `暂不支持自动下发：${d.action}`
    return
  }
  aiDispBusy.value = true
  try {
    await createAgentCommand(aid, d.action, params)
    okMsg.value = `已下发：${d.label || d.action}（待 Agent 执行）`
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    aiDispBusy.value = false
  }
}

async function loadAttckBoard() {
  try {
    if (!agents.value.length) await refresh()
    const r = await attckBoard({ agentId: attckAgent.value, days: attckDays.value })
    attckCols.value = r?.columns || []
    attckTop.value = r?.top_techniques || []
    attckHeat.value = r?.heat || []
    attckHosts.value = r?.top_hosts || []
    attckTotal.value = r?.event_total || 0
    attckCovered.value = r?.tactics_covered || 0
    attckItems.value = r?.items || []
    attckHigh.value = r?.high_total || 0
    attckOpen.value = r?.open_total || 0
    attckUnmapped.value = r?.unmapped_total || 0
    const { tactic, tech } = attckSel.value
    if ((tactic && !attckHeat.value.some((h) => h.tactic === tactic && h.count))
      || (tech && !attckTop.value.some((t) => t.id === tech))) {
      clearAttckSel()
    }
  } catch (e) { error.value = e?.message || String(e) }
}

function attckStepStyle(t) {
  if (!t.count) return {}
  const max = Math.max(1, ...attckHeat.value.map((h) => h.count || 0))
  const r = Math.min(1, t.count / max)
  return {
    '--ak-bg': `rgba(225, 29, 46, ${(0.05 + 0.17 * r).toFixed(3)})`,
    '--ak-bar': `rgba(225, 29, 46, ${(0.35 + 0.65 * r).toFixed(3)})`,
  }
}

function selectAttckTactic(tactic) {
  attckSel.value = attckSel.value.tactic === tactic && !attckSel.value.tech
    ? { tactic: '', tech: '' }
    : { tactic, tech: '' }
}

function selectAttckTech(t) {
  const cur = attckSel.value
  attckSel.value = cur.tech === t.id ? { tactic: cur.tactic, tech: '' } : { tactic: cur.tactic, tech: t.id }
}

function clearAttckSel() {
  attckSel.value = { tactic: '', tech: '' }
}

function attckRankPct(count) {
  const max = Math.max(1, ...(attckTechList.value || []).map((t) => Number(t.count) || 0))
  return Math.max(6, Math.round((100 * (Number(count) || 0)) / max))
}

function attckHostPct(count) {
  const max = Math.max(1, ...(attckHosts.value || []).map((h) => Number(h.count) || 0))
  return Math.max(8, Math.round((100 * (Number(count) || 0)) / max))
}

function focusAttckTopHost() {
  const h = attckHosts.value?.[0]
  if (h) filterAttckByHost(h)
}

async function filterAttckByHost(h) {
  if (!h) return
  const host = h.host || h.hostname || ''
  const aid = h.agent_id || ''
  if (aid) {
    attckAgent.value = aid
  } else if (host) {
    const hit = agents.value.find((a) => (a.hostname || '') === host)
    if (hit) attckAgent.value = hit.agent_id
  }
  await loadAttckBoard()
}

async function loadNotify() {
  try {
    const r = await getNotifyConfig()
    notifyForm.value = { ...notifyForm.value, ...(r?.config || {}) }
  } catch (e) { error.value = e?.message || String(e) }
}

async function saveNotify() {
  saving.value = true
  try {
    await setNotifyConfig({ ...notifyForm.value })
    okMsg.value = '通知配置已保存'
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    saving.value = false
  }
}

async function doTestNotify() {
  notifyTestResult.value = null
  try {
    await setNotifyConfig({ ...notifyForm.value })
    notifyTestResult.value = await testNotify()
  } catch (e) { error.value = e?.message || String(e) }
}

async function loadStorage() {
  try {
    storeInfo.value = await storeStats()
  } catch (e) { error.value = e?.message || String(e) }
}

async function doPurge() {
  const rc = storeInfo.value?.retention || {}
  if (!window.confirm(`按保留期清理：时间线超过 ${rc.timeline_days} 天、已关闭事件超过 ${rc.events_days} 天的记录将被删除，继续？`)) return
  try {
    const r = await storePurge()
    okMsg.value = `已清理 时间线 ${r.timeline_deleted || 0} 条，事件 ${r.events_deleted || 0} 条`
    await loadStorage()
  } catch (e) { error.value = e?.message || String(e) }
}

async function doStoreSearch() {
  if (!storeQ.value.trim()) return
  try {
    const r = await storeSearch(storeQ.value.trim())
    storeHits.value = r?.items || []
  } catch (e) { error.value = e?.message || String(e) }
}

async function doRollbackUpgrade() {
  if (!upAgentIds.value.length) return
  if (!window.confirm(`对 ${upAgentIds.value.length} 台终端回滚到升级前版本？`)) return
  upPushBusy.value = true
  try {
    const rs = await Promise.all(upAgentIds.value.map((id) => createAgentCommand(id, 'rollback_upgrade', {}).catch(() => null)))
    okMsg.value = `已下发回滚指令 ${rs.filter(Boolean).length}/${rs.length}`
  } finally {
    upPushBusy.value = false
  }
}

async function loadAttackStory() {
  const ev = activeEvent.value
  if (!ev) return
  try {
    const r = await attackStory({ agentId: ev.agent_id, eventId: ev.id, limit: 60 })
    storyNodes.value = r?.nodes || []
    storyTech.value = r?.techniques || []
  } catch (e) { error.value = e?.message || String(e) }
}

function threatTreeHasKids(id) {
  const nodes = threatTree.value?.nodes || []
  return nodes.some((n) => n.parent_id === id)
}

function toggleThreatTreeNode(id) {
  const cur = tvTreeExpanded.value[id]
  tvTreeExpanded.value = { ...tvTreeExpanded.value, [id]: cur === false }
}

const threatGraphVisibleNodes = computed(() => {
  const nodes = threatTree.value?.nodes || []
  const hitId = threatTree.value?.hit_id
  if (!nodes.length) return []
  if (!hitId) return nodes
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]))
  const keep = new Set()
  let cur = byId[hitId]
  while (cur) {
    keep.add(cur.id)
    cur = cur.parent_id ? byId[cur.parent_id] : null
  }
  const stack = [hitId]
  const exp = tvTreeExpanded.value || {}
  while (stack.length) {
    const id = stack.pop()
    if (exp[id] === false) continue
    for (const n of nodes) {
      if (n.parent_id === id && !keep.has(n.id)) {
        keep.add(n.id)
        stack.push(n.id)
      }
    }
  }
  return nodes.filter((n) => keep.has(n.id))
})

const threatGraphLayers = computed(() => {
  const nodes = threatGraphVisibleNodes.value
  if (!nodes.length) return []
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]))
  const rootId = threatTree.value?.root_id
  let root = (rootId && byId[rootId]) || nodes.find((n) => !n.parent_id || !byId[n.parent_id]) || nodes[0]
  const depthMemo = new Map()
  function depthOf(n) {
    if (!n?.id) return 0
    if (depthMemo.has(n.id)) return depthMemo.get(n.id)
    let d = 0
    if (n.parent_id && byId[n.parent_id]) d = depthOf(byId[n.parent_id]) + 1
    depthMemo.set(n.id, d)
    return d
  }
  void root
  const maxD = Math.max(...nodes.map((n) => depthOf(n)))
  const layers = []
  for (let d = 0; d <= maxD; d += 1) {
    const col = nodes
      .filter((n) => depthOf(n) === d)
      .sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')))
    if (col.length) layers.push(col)
  }
  const rowMemo = new Map()
  layers[0]?.forEach((n, i) => rowMemo.set(n.id, i))
  for (let d = 1; d < layers.length; d += 1) {
    layers[d] = [...layers[d]].sort((a, b) => {
      const ra = rowMemo.get(a.parent_id)
      const rb = rowMemo.get(b.parent_id)
      if (ra !== undefined && rb !== undefined && ra !== rb) return ra - rb
      if (ra !== undefined && rb === undefined) return -1
      if (rb !== undefined && ra === undefined) return 1
      return String(a.name || '').localeCompare(String(b.name || ''))
    })
    layers[d].forEach((n, i) => rowMemo.set(n.id, i))
  }
  return layers
})

const threatGraphLayout = computed(() => {
  const layers = threatGraphLayers.value
  const COL_W = 268
  const NODE_W = 228
  // 名称 + PID + 两行命令行 +「威胁命中」标签，原先 86px 会裁掉路径/命令行
  const NODE_H = tvReadable.value ? 128 : 108
  const GAP = 22
  const PAD = 20
  if (!layers.length) {
    return { layers: [], paths: [], width: 0, height: 0, positions: {}, colW: COL_W }
  }
  const positions = {}
  layers.forEach((col, ci) => {
    col.forEach((n, ri) => {
      const top = PAD + ri * (NODE_H + GAP)
      const globalLeft = ci * COL_W + PAD
      const cx = globalLeft + NODE_W / 2
      const cy = top + NODE_H / 2
      positions[n.id] = {
        x: cx,
        y: cy,
        col: ci,
        style: {
          top: `${top}px`,
          left: `${PAD}px`,
          width: `${NODE_W}px`,
          minHeight: `${NODE_H}px`,
          height: `${NODE_H}px`,
        },
      }
    })
  })
  const paths = []
  const byId = Object.fromEntries(
    layers.flat().map((n) => [n.id, n]),
  )
  for (const child of layers.flat()) {
    const parent = child.parent_id ? byId[child.parent_id] : null
    if (!parent) continue
    const pa = positions[parent.id]
    const pb = positions[child.id]
    if (!pa || !pb) continue
    const x1 = pa.col * COL_W + PAD + NODE_W
    const y1 = pa.y
    const x2 = pb.col * COL_W + PAD
    const y2 = pb.y
    const midX = x1 + Math.max(28, (x2 - x1) * 0.5)
    const repaired = !!(child.link_repaired || parent.synthetic || parent.missing)
    const hot = !!(child.is_hit || parent.is_hit)
    paths.push({
      d: `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`,
      repaired,
      hot,
    })
  }
  const maxRows = Math.max(...layers.map((c) => c.length), 1)
  const height = PAD * 2 + maxRows * (NODE_H + GAP) - GAP
  return {
    layers,
    paths,
    width: Math.max(PAD * 2 + layers.length * COL_W, 320),
    height,
    positions,
    colW: COL_W,
  }
})

function threatNodeStyle(id) {
  return threatGraphLayout.value.positions[id]?.style || {}
}

const threatDropChainSteps = computed(() => threatTree.value?.drop_chain?.steps || [])
const threatDropChainEdges = computed(() => threatTree.value?.drop_chain?.edges || [])

function threatDropEdgeLabel(index) {
  if (index <= 0) return ''
  const e = threatDropChainEdges.value.find((x) => x.to === index)
  return e?.label || '关联'
}

function threatDropKindLabel(s) {
  if (s?.kind === 'file') return '释放文件'
  if (s?.role === 'parent') return '父进程'
  if (s?.role === 'hit') return '威胁进程'
  if (s?.role === 'child') return '子进程'
  return '进程'
}

function onThreatGraphNode(n) {
  if (n?.is_hit) threatPanelNode.value = 'hit'
}

async function loadThreatProcessTree() {
  const ev = activeEvent.value
  if (!ev?.agent_id) return
  threatTreeBusy.value = true
  try {
    const r = await threatProcessTree({ agentId: ev.agent_id, eventId: ev.id, maxNodes: 72 })
    threatTree.value = r
    const nodes = r?.nodes || []
    const hitNode = nodes.find((n) => n.is_hit) || nodes.find((n) => n.id === r?.hit_id)
    if (hitNode) {
      mergeThreatEvidenceEnrich({
        name: hitNode.name,
        process_name: hitNode.name,
        path: hitNode.path,
        image: hitNode.path,
        command_line: hitNode.command_line,
        pid: hitNode.pid,
        ppid: hitNode.ppid,
      })
      const par = nodes.find((n) => n.id === hitNode.parent_id)
      if (par?.name && !par.synthetic) mergeThreatEvidenceEnrich({ parent_name: par.name })
    }
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]))
    const exp = {}
    for (const n of nodes) exp[n.id] = true
    let cur = byId[r?.hit_id]
    while (cur) {
      exp[cur.id] = true
      cur = byId[cur.parent_id]
    }
    tvTreeExpanded.value = exp
    tvZoom.value = 1
  } catch {
    threatTree.value = null
  } finally {
    threatTreeBusy.value = false
  }
}

async function openEventById(id) {
  if (!id) return
  try {
    const r = await getEvent(id)
    if (r?.item) openEvent(r.item)
  } catch (e) { error.value = e?.message || String(e) }
}

async function loadUpgradePage() {
  try {
    if (!agents.value.length) await refresh()
    const [r, cmds, fd] = await Promise.all([
      listUpgradePackages(),
      listAllAgentCommands('', 120).catch(() => ({ items: [] })),
      getFleetDrift(45).catch(() => ({ items: [] })),
    ])
    upPackages.value = r?.items || []
    upCommands.value = cmds?.items || []
    const map = {}
    for (const it of fd?.items || []) {
      if (it?.agent_id) map[it.agent_id] = it
    }
    fleetDriftByAgent.value = map
    await loadDiagHistory()
  } catch (e) { error.value = e?.message || String(e) }
}

function onUpFile(ev) {
  const f = ev?.target?.files?.[0]
  upFile.value = f || null
  if (f && !upVer.value) {
    const m = String(f.name).match(/(\d+\.\d+\.\d+)/)
    if (m) upVer.value = m[1]
  }
}

async function doUploadUpgrade() {
  if (!upFile.value) return
  upBusy.value = true
  upError.value = ''
  upOk.value = ''
  try {
    const r = await uploadUpgradePackage(upFile.value, upVer.value, upNote.value)
    upOk.value = `已上传 ${r.version} · ${String(r.sha256 || '').slice(0, 16)}…`
    upFile.value = null
    await loadUpgradePage()
    if (r.id) upPkgId.value = r.id
  } catch (e) {
    upError.value = e?.message || String(e)
  } finally {
    upBusy.value = false
  }
}

async function doPushUpgrade() {
  if (!upPkgId.value || !upAgentIds.value.length) return
  if (!window.confirm(`向 ${upAgentIds.value.length} 台终端推送升级？`)) return
  upPushBusy.value = true
  try {
    const r = await pushUpgradePackage(upPkgId.value, upAgentIds.value)
    const ok = (r.results || []).filter((x) => x.ok).length
    okMsg.value = `已下发升级指令 ${ok}/${(r.results || []).length}（版本 ${r.version}）`
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    upPushBusy.value = false
  }
}

async function doDelUpgrade(id) {
  if (!window.confirm('删除该升级包？')) return
  try {
    await deleteUpgradePackage(id)
    if (upPkgId.value === id) upPkgId.value = ''
    await loadUpgradePage()
  } catch (e) { error.value = e?.message || String(e) }
}

function fmtNum(n) {
  const x = Number(n) || 0
  return x.toLocaleString('zh-CN')
}

function fmtSize(n) {
  const x = Number(n) || 0
  if (x < 1024) return `${x} B`
  if (x < 1024 * 1024) return `${(x / 1024).toFixed(1)} KB`
  return `${(x / 1024 / 1024).toFixed(1)} MB`
}

async function doImportIoc() {
  if (!iocText.value.trim()) return
  try {
    const r = await importIoc(iocText.value, iocType.value)
    okMsg.value = `已导入 ${r?.imported || 0} 条`
    iocText.value = ''
    await loadIoc()
  } catch (e) { error.value = e?.message || String(e) }
}

async function delIoc(id) {
  if (!window.confirm('删除 IOC？')) return
  try { await deleteIoc(id); await loadIoc() } catch (e) { error.value = e?.message || String(e) }
}

async function loadSeqRules() {
  try {
    const r = await listSeqRules()
    seqRules.value = r?.items || []
  } catch (e) { error.value = e?.message || String(e) }
}

function seqStepsPreview(r) {
  const steps = r.steps || []
  if (!steps.length) return '—'
  return steps.map((s, i) => {
    const bit = s.etype_contains || s.summary_contains || (s.name_regex ? 'regex' : '?')
    return `${i + 1}.${bit}`
  }).join(' → ')
}

function startCreateSeq() {
  seqCreating.value = true
  editingSeq.value = null
  seqFormError.value = ''
  seqForm.value = emptySeqForm()
}

function startEditSeq(r) {
  seqCreating.value = false
  editingSeq.value = r
  seqFormError.value = ''
  const steps = (r.steps || []).map((s) => ({
    etype_contains: s.etype_contains || '',
    summary_contains: s.summary_contains || '',
    name_regex: s.name_regex || '',
  }))
  while (steps.length < 2) {
    steps.push({ etype_contains: 'process', summary_contains: '', name_regex: '' })
  }
  seqForm.value = {
    title: r.title || '',
    severity: r.severity || 'high',
    window_sec: r.window_sec || 120,
    enabled: !!r.enabled,
    note: r.note || '',
    steps,
  }
}

function cancelSeqForm() {
  seqCreating.value = false
  editingSeq.value = null
  seqFormError.value = ''
  seqForm.value = emptySeqForm()
}

function applySeqTemplate(t) {
  seqForm.value = {
    title: t.title,
    severity: t.severity,
    window_sec: t.window_sec,
    enabled: true,
    note: t.note || '',
    steps: t.steps.map((s) => ({ ...s })),
  }
}

function addSeqStep() {
  if (seqForm.value.steps.length >= 6) return
  seqForm.value.steps.push({ etype_contains: 'process', summary_contains: '', name_regex: '' })
}

function removeSeqStep(idx) {
  if (seqForm.value.steps.length <= 2) return
  seqForm.value.steps.splice(idx, 1)
}

async function saveSeqForm() {
  seqSaving.value = true
  seqFormError.value = ''
  try {
    const f = seqForm.value
    const payload = {
      id: seqCreating.value ? undefined : editingSeq.value?.id,
      title: String(f.title || '').trim(),
      severity: f.severity,
      window_sec: f.window_sec,
      enabled: f.enabled,
      note: f.note,
      steps: f.steps,
    }
    if (!payload.title) throw new Error('请填写标题')
    await upsertSeqRule(payload)
    okMsg.value = seqCreating.value ? '序列已创建' : '序列已更新'
    setTimeout(() => { okMsg.value = '' }, 2000)
    cancelSeqForm()
    await loadSeqRules()
  } catch (e) {
    seqFormError.value = e?.message || String(e)
  } finally {
    seqSaving.value = false
  }
}

async function toggleSeq(r, on) {
  try {
    await upsertSeqRule({ ...r, enabled: on, steps: r.steps || [] })
    await loadSeqRules()
  } catch (e) { error.value = e?.message || String(e) }
}

async function removeSeq(r) {
  if (!window.confirm(`删除序列「${r.title}」？`)) return
  try {
    await deleteSeqRule(r.id)
    if (editingSeq.value?.id === r.id) cancelSeqForm()
    await loadSeqRules()
    okMsg.value = '已删除'
    setTimeout(() => { okMsg.value = '' }, 2000)
  } catch (e) { error.value = e?.message || String(e) }
}

async function loadGroups() {
  try {
    const r = await listAgentGroups()
    groupItems.value = r?.items || []
  } catch (e) { error.value = e?.message || String(e) }
}

async function saveGroup() {
  if (!groupName.value.trim()) return
  const ids = groupIds.value.split(/[,，\s]+/).map((x) => x.trim()).filter(Boolean)
  try {
    await upsertAgentGroup({ name: groupName.value.trim(), agent_ids: ids })
    groupName.value = ''
    groupIds.value = ''
    await loadGroups()
    okMsg.value = '分组已保存'
  } catch (e) { error.value = e?.message || String(e) }
}

async function loadAudit() {
  try {
    const r = await listAgentAudit(200)
    auditItems.value = r?.items || []
  } catch (e) { error.value = e?.message || String(e) }
}

async function loadTags() {
  try {
    const r = await getAgentTags()
    tagMap.value = r?.items || {}
  } catch { /* ignore */ }
}

async function saveHostTags(a) {
  const tags = hostTagEdit.value.split(/[,，\s]+/).map((x) => x.trim()).filter(Boolean)
  try {
    await setAgentTags(a.agent_id, tags)
    await loadTags()
    okMsg.value = '标签已保存'
  } catch (e) { error.value = e?.message || String(e) }
}

async function savePolicy() {
  saving.value = true
  try {
    const {
      fim_paths_text: fimText,
      log_tail_paths_text: logTailText,
      winevent_channels_text: wevtText,
      remote_ops_read_only,
      remote_ops_run_cmd,
      remote_ops_shell,
      remote_ops_enabled,
      ...rest
    } = policyForm.value
    const fimPaths = String(fimText || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean).slice(0, 50)
    const logTailPaths = String(logTailText || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean).slice(0, 20)
    const wineventChannels = String(wevtText || '').split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean).slice(0, 30)
    const r = await setAgentPolicy({
      ...rest,
      fim_paths: fimPaths,
      log_tail_paths: logTailPaths,
      winevent_channels: wineventChannels,
      remote_ops_enabled,
      remote_ops: {
        enabled: remote_ops_enabled,
        read_only: remote_ops_read_only,
        run_cmd_enabled: remote_ops_run_cmd,
        shell_enabled: remote_ops_shell,
        shell_max_minutes: 15,
      },
    }, 'global')
    policyRev.value = r?.rev || policyRev.value
    okMsg.value = '策略已保存，终端下次心跳生效'
    setTimeout(() => { okMsg.value = '' }, 2500)
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    saving.value = false
  }
}

async function addWl() {
  if (!wlValue.value.trim()) return
  try {
    await addWhitelist(wlKind.value, wlValue.value.trim(), wlNote.value.trim(), { rule: wlRule.value.trim() })
    wlValue.value = ''
    wlNote.value = ''
    wlRule.value = ''
    await loadWhitelistOnly()
    okMsg.value = '加白已保存，sync 后终端生效'
    setTimeout(() => { okMsg.value = '' }, 2500)
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

async function delWl(id) {
  if (!window.confirm('删除该加白条目？删除后同类告警会重新产生。')) return
  try {
    await deleteWhitelist(id)
    await loadWhitelistOnly()
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

async function toggleWl(w) {
  try {
    await setWhitelistEnabled(w.id, !w.enabled)
    await loadWhitelistOnly()
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

function agentLabel(aid) {
  const a = agents.value.find((x) => x.agent_id === aid)
  return a?.hostname || short(aid)
}

async function openAllow(e) {
  if (!e?.id) return
  allowDlg.value = {
    eventId: e.id, title: e.title || '', agentId: e.agent_id || '', hostname: e.hostname || '',
    items: [], picks: [], kind: 'title', value: '', rulePrefix: '', limitRule: true,
    scope: 'host', note: '', applyExisting: true, loading: true, busy: false, err: '',
  }
  try {
    const r = await eventAllowCandidates(e.id)
    const d = allowDlg.value
    if (!d || d.eventId !== e.id) return
    d.items = r?.items || []
    d.rulePrefix = r?.rule_prefix && r.rule_prefix !== d.title ? r.rule_prefix : ''
    if (r?.hostname) d.hostname = r.hostname
    d.loading = false
    if (d.items.length) {
      const dp = Array.isArray(r?.default_picks) && r.default_picks.length ? r.default_picks : [0]
      d.picks = dp.filter((i) => i >= 0 && i < d.items.length)
      if (!d.picks.length) d.picks = [0]
      syncAllowValueFromPicks()
    }
  } catch (err) {
    if (allowDlg.value) {
      allowDlg.value.loading = false
      allowDlg.value.err = err?.message || String(err)
    }
  }
}

function syncAllowValueFromPicks() {
  const d = allowDlg.value
  if (!d?.items?.length || !d.picks?.length) return
  if (d.picks.length === 1) {
    const c = d.items[d.picks[0]]
    if (c) {
      d.kind = c.kind
      d.value = c.value
    }
  }
}

function toggleAllowPick(i) {
  const d = allowDlg.value
  if (!d) return
  const set = new Set(d.picks || [])
  if (set.has(i)) set.delete(i)
  else set.add(i)
  d.picks = [...set].sort((a, b) => a - b)
  syncAllowValueFromPicks()
}

function allowPickAll() {
  const d = allowDlg.value
  if (!d?.items?.length) return
  d.picks = d.items.map((_, idx) => idx)
}

function allowPickClear() {
  const d = allowDlg.value
  if (!d) return
  d.picks = []
}

async function submitAllow() {
  const d = allowDlg.value
  if (!d || !allowSubmitReady.value) return
  const picks = d.picks?.length ? [...d.picks] : []
  if (!picks.length) {
    d.err = '请至少勾选一条加白维度'
    return
  }
  d.busy = true
  d.err = ''
  let ignored = 0
  try {
    for (const i of picks) {
      const c = d.items[i]
      if (!c) continue
      const value = picks.length === 1 ? d.value.trim() : String(c.value || '').trim()
      if (!value) continue
      const r = await addWhitelist(c.kind, value, d.note.trim(), {
        agent_id: d.scope === 'host' ? d.agentId : '',
        rule: c.kind !== 'title' && d.limitRule ? d.rulePrefix : '',
        source_event_id: d.eventId,
        apply_existing: d.applyExisting,
      })
      ignored += Number(r?.ignored || 0)
    }
    allowDlg.value = null
    okMsg.value = ignored
      ? `已加白 ${picks.length} 条规则，${ignored} 条已有告警标为无需处置`
      : (picks.length > 1 ? `已加白 ${picks.length} 条规则` : '已加白，后续同类告警不再产生')
    setTimeout(() => { okMsg.value = '' }, 4000)
    await loadWhitelistOnly()
    await loadEvents(false)
    if (activeEvent.value?.id === d.eventId && ignored) {
      activeEvent.value = { ...activeEvent.value, status: 'ignored' }
    }
  } catch (err) {
    d.err = err?.message || String(err)
  } finally {
    if (allowDlg.value) allowDlg.value.busy = false
  }
}

let eventsSyncInflight = null
let lastEventsSyncAt = 0
const EVENTS_CACHE_KEY = 'edr_events_cache_v1'

function applyEventsList(items) {
  if (!Array.isArray(items)) return
  allEvents.value = items
  events.value = allEvents.value
  openEventCount.value = allEvents.value.length
  try {
    sessionStorage.setItem(EVENTS_CACHE_KEY, JSON.stringify({
      at: Date.now(),
      items: items.slice(0, 300),
    }))
  } catch { /* quota */ }
}

function hydrateEventsCache() {
  try {
    const raw = JSON.parse(sessionStorage.getItem(EVENTS_CACHE_KEY) || 'null')
    if (!Array.isArray(raw?.items) || !raw.items.length) return false
    // 缓存超过 30 分钟仍可先显示，随后 API 覆盖
    applyEventsList(raw.items)
    return true
  } catch {
    return false
  }
}

async function loadEvents(showErr = true, syncFromTimeline = false) {
  try {
    // 始终先拉轻量列表（sync=0）；绝不因晋升卡住首屏
    const quick = await listEvents({ status: '', limit: 500, sync: false })
    if (Array.isArray(quick?.items)) applyEventsList(quick.items)

    const wantSync = syncFromTimeline || !allEvents.value.length
    const due = Date.now() - lastEventsSyncAt > 60000
    if (wantSync && due && !eventsSyncInflight) {
      eventsSyncInflight = listEvents({ status: '', limit: 500, sync: true })
        .then((synced) => {
          lastEventsSyncAt = Date.now()
          if (Array.isArray(synced?.items)) applyEventsList(synced.items)
          return synced
        })
        .catch((e) => {
          if (showErr && !allEvents.value.length) error.value = e?.message || String(e)
        })
        .finally(() => { eventsSyncInflight = null })
    }
    if ((wantSync || syncFromTimeline) && !timelineItems.value.length) {
      listTimeline({ limit: 80 }).then((tl) => {
        timelineItems.value = tl?.items || []
      }).catch(() => {})
    }
  } catch (e) {
    if (showErr && !allEvents.value.length) error.value = e?.message || String(e)
  }
}

async function openEvent(e) {
  if (!e?.id) return
  section.value = 'detect'
  threatTab.value = 'graph'
  threatPanelNode.value = 'hit'
  dismissRespToast()
  respToastCmdKey = ''
  storyNodes.value = []
  storyTech.value = []
  relatedPayload.value = null
  threatEvidenceEnrich.value = {}
  threatProcessSnap.value = []
  try {
    const r = await getEvent(e.id)
    activeEvent.value = r?.item || e
    if (detailLooksThinForEnrich(activeEvent.value)) {
      try {
        const er = await enrichEventDetail(e.id)
        if (er?.item) activeEvent.value = er.item
      } catch { /* 单条 enrich 失败仍用 getEvent 结果 */ }
    }
  } catch {
    activeEvent.value = e
  }
  listFocusId.value = e.id
  listFocusEvent.value = activeEvent.value
  if (page.value === 'malware') eventListReturnPage.value = 'malware'
  else if (page.value === 'events') eventListReturnPage.value = 'events'
  page.value = 'threat-view'
  // 预载同主机时间线，便于威胁图补全父进程名
  const aid = activeEvent.value?.agent_id
  if (aid) {
    tlAgentId.value = aid
    listTimeline({ agentId: aid, limit: 200 }).then((r) => {
      timelineItems.value = r?.items || []
    }).catch(() => {})
    getSnapshot(aid, 'process').then((r) => {
      if (activeEvent.value?.agent_id !== aid) return
      const items = r?.items || r?.snap?.items || []
      threatProcessSnap.value = items
      const flat = evidenceFlatOf(parseEventEvidence(activeEvent.value))
      const pid = flat.pid != null && flat.pid !== '' ? String(flat.pid) : ''
      const ppid = flat.ppid != null && flat.ppid !== '' ? String(flat.ppid) : ''
      const hit = pid ? items.find((row) => String(row.pid) === pid) : null
      const par = ppid ? items.find((row) => String(row.pid) === ppid) : null
      mergeThreatEvidenceEnrich({
        ...(hit ? pickProcessSnapFields(hit) : {}),
        ...(par?.name ? { parent_name: par.name } : {}),
      })
      enrichThreatFromProcessDb(aid, flat)
    }).catch(() => {
      const flat = evidenceFlatOf(parseEventEvidence(activeEvent.value))
      enrichThreatFromProcessDb(aid, flat)
    })
  }
  loadRespCommands()
  loadAttackStory()
  loadThreatProcessTree()
  getRelatedEvents(e.id, 20).then((r) => {
    if (activeEvent.value?.id === e.id) relatedPayload.value = r
  }).catch(() => { relatedPayload.value = null })
}

function closeThreat() {
  activeEvent.value = null
  page.value = eventListReturnPage.value === 'malware' ? 'malware' : 'events'
  loadEvents()
}

function jumpToHost() {
  const id = activeEvent.value?.agent_id
  const a = agents.value.find((x) => x.agent_id === id)
  if (a) openHost(a)
}

function jumpToEvidence() {
  const id = activeEvent.value?.agent_id
  const mod = activeEvent.value?.module
  const a = agents.value.find((x) => x.agent_id === id)
  if (!a) return
  if (mod && LABELS[mod]) module.value = mod
  openHost(a, 'hosts')
}

function rowKey(row) {
  if (!row) return ''
  return [row.pid, row.name, row.task_name, row.path, row.local, row.command].filter(Boolean).join('|')
}

async function loadSnap(m, { silent = false, keepRow = false, syncGroup = true } = {}) {
  const switched = module.value !== m
  module.value = m
  if (syncGroup && hostTabGroup.value !== 'remote') syncHostTabGroup(m)
  if (switched) {
    snapRow.value = null
    snapQ.value = ''
  }
  if (!selected.value?.agent_id) return
  if (!silent) snapLoading.value = true
  snapError.value = ''
  const prevKey = keepRow || !switched ? rowKey(snapRow.value) : ''
  try {
    const r = await getSnapshot(selected.value.agent_id, m)
    snap.value = r?.item || r || null
    const items = snap.value?.items || []
    if (m === 'sysinfo') {
      snapRow.value = null
    } else if (items.length) {
      const found = prevKey ? items.find((x) => rowKey(x) === prevKey) : null
      snapRow.value = found || (switched || !snapRow.value ? items[0] : snapRow.value)
    } else {
      snapRow.value = null
    }
  } catch (e) {
    snap.value = null
    if (!silent) snapError.value = e?.message || '无快照'
  } finally {
    if (!silent) snapLoading.value = false
  }
}

function openHost(a, dest = 'hosts') {
  selected.value = a
  section.value = 'asset'
  page.value = 'hosts'
  hostHdrMore.value = false
  hostHealthOpen.value = false // 默认收起，把版面留给进程/资产表
  if (!module.value) module.value = 'process'
  loadSnap(module.value)
}

function backFromHost() {
  stopHostRemotePoll()
  stopHostRemoteShellPoll()
  hostRemoteShellId.value = ''
  hostRemoteShellPhase.value = 'idle'
  hostRemoteShellLines.value = []
  hostHdrMore.value = false
  hostHealthOpen.value = false
  selected.value = null
  snap.value = null
  snapRow.value = null
  hostRiskItems.value = []
  hostRemoteCommands.value = []
  page.value = 'hosts'
}

async function removeHost(a) {
  if (!a?.agent_id) return
  const tip = a.online
    ? `仅删除平台记录「${a.hostname || a.agent_id}」（快照/威胁/时间线）？\nAgent 若仍在跑会重新注册。若要卸掉客户端请先点「远程卸载」。`
    : `删除主机「${a.hostname || a.agent_id}」及其快照、威胁、时间线？`
  if (!window.confirm(tip)) return
  try {
    await deleteAgent(a.agent_id)
    if (selected.value?.agent_id === a.agent_id) selected.value = null
    okMsg.value = '平台记录已删除（含威胁与时间线）'
    setTimeout(() => { okMsg.value = '' }, 2500)
    await refresh()
    await loadEvents()
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

async function uninstallHost(a) {
  if (!a?.agent_id) return
  if (!a.online) {
    error.value = '终端离线，无法远程卸载'
    return
  }
  const tip = `向「${a.hostname || a.agent_id}」下发远程卸载？\n将停止并删除 Agent 服务（约数秒后生效），随后可再「删除记录」清理平台数据。`
  if (!window.confirm(tip)) return
  try {
    await createAgentCommand(a.agent_id, 'uninstall_agent', { remove_files: true })
    okMsg.value = '卸载指令已下发，等待终端心跳执行'
    setTimeout(() => { okMsg.value = '' }, 3000)
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

async function doDownload() {
  dlBusy.value = true
  dlProgress.value = '准备安装包…'
  dlError.value = ''
  try {
    await downloadInstallPackage(({ phase, received, total }) => {
      if (phase !== 'download') return
      if (total > 0) {
        const pct = Math.min(100, Math.round((received / total) * 100))
        const mb = (received / 1048576).toFixed(1)
        const tmb = (total / 1048576).toFixed(1)
        dlProgress.value = `下载中 ${pct}%（${mb}/${tmb} MB）`
      } else {
        dlProgress.value = `下载中 ${(received / 1048576).toFixed(1)} MB…`
      }
    })
    okMsg.value = '安装包已开始下载'
    setTimeout(() => { okMsg.value = '' }, 2000)
  } catch (e) {
    dlError.value = e?.message || String(e)
  } finally {
    dlBusy.value = false
    dlProgress.value = ''
  }
}

async function loadSettings() {
  try {
    const j = await edrGetSettings()
    agentServerUrl.value = j.agent_server_url || ''
  } catch { /* ignore */ }
  try {
    if (!agentRules.value.length) await loadRules()
  } catch { /* ignore */ }
}

async function saveSettings() {
  saving.value = true
  error.value = ''
  try {
    const j = await edrSaveSettings({ agent_server_url: agentServerUrl.value })
    agentServerUrl.value = j.agent_server_url || ''
    flashOk('已保存')
  } catch (e) {
    error.value = e?.message || String(e)
  } finally {
    saving.value = false
  }
}

async function rotateKey() {
  if (!window.confirm('轮换后旧安装包将失效，确定？')) return
  try {
    await rotateEnrollKey()
    flashOk('接入密钥已轮换')
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

function flashOk(msg) {
  okMsg.value = msg
  setTimeout(() => { okMsg.value = '' }, 2200)
}

// ---------- 账号 ----------

const edrUsers = ref([])
const roleLabels = ref({ admin: '管理员', analyst: '分析员', readonly: '只读' })
const dlg = ref('')
const dlgForm = ref({})
const dlgBusy = ref(false)
const dlgError = ref('')
const dlgTitle = computed(() => ({
  pw: '修改我的密码', create: '新建账号', reset: '重置密码',
}[dlg.value] || ''))

function fmtEpoch(sec) {
  if (!sec) return '—'
  const d = new Date(Number(sec) * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

async function loadEdrUsers() {
  if (!isAdmin.value) return
  try {
    const r = await edrListUsers()
    edrUsers.value = r.items || []
    if (r.roles) roleLabels.value = r.roles
  } catch (e) {
    error.value = e?.message || String(e)
  }
}

function openDlg(kind, form = {}) {
  userMenuOpen.value = false
  dlg.value = kind
  dlgForm.value = form
  dlgError.value = ''
}

function openPwDialog() { openDlg('pw', { current: '', password: '', password2: '' }) }
function openUserForm() { openDlg('create', { username: '', display_name: '', role: 'analyst', password: '' }) }
function openResetPw(u) { openDlg('reset', { target: u, password: '' }) }

async function submitDlg() {
  const f = dlgForm.value
  dlgError.value = ''
  if (dlg.value === 'pw' && f.password !== f.password2) {
    dlgError.value = '两次输入的新密码不一致'
    return
  }
  dlgBusy.value = true
  try {
    if (dlg.value === 'pw') {
      const r = await edrChangePassword(f.current, f.password)
      if (r?.user) emit('user-updated', r.user)
      flashOk('密码已修改')
    } else if (dlg.value === 'create') {
      await edrCreateUser({ ...f, must_change: true })
      flashOk(`账号 ${f.username} 已创建`)
      await loadEdrUsers()
    } else if (dlg.value === 'reset') {
      await edrResetPassword(f.target.id, f.password)
      flashOk(`已重置 ${f.target.username} 的密码`)
      await loadEdrUsers()
    }
    dlg.value = ''
  } catch (e) {
    dlgError.value = e?.message || String(e)
  } finally {
    dlgBusy.value = false
  }
}

async function changeUserRole(u, role) {
  if (role === u.role) return
  try {
    await edrUpdateUser(u.id, { role })
    flashOk('角色已更新，对方需重新登录')
  } catch (e) {
    error.value = e?.message || String(e)
  }
  await loadEdrUsers()
}

async function toggleUserEnabled(u) {
  if (u.enabled && !window.confirm(`禁用账号「${u.username}」？对方会被立即下线。`)) return
  try {
    await edrUpdateUser(u.id, { enabled: !u.enabled })
    flashOk(u.enabled ? '已禁用' : '已启用')
  } catch (e) {
    error.value = e?.message || String(e)
  }
  await loadEdrUsers()
}

async function removeUser(u) {
  if (!window.confirm(`删除账号「${u.username}」？此操作不可恢复。`)) return
  try {
    await edrDeleteUser(u.id)
    flashOk('已删除')
  } catch (e) {
    error.value = e?.message || String(e)
  }
  await loadEdrUsers()
}

function closeUserMenu() { userMenuOpen.value = false }

let snapTimer = null

watch([section, page, eventListReturnPage, rulesSection, () => activeEvent.value?.id], saveNavState)

watch(hostRemoteSubTab, (tab) => {
  if (tab === 'files' && selected.value?.online) hostRemoteFsLoadVolumes()
  if (tab === 'shell') nextTick(() => { hostRemoteShellInputRef.value?.focus() })
})

watch(() => selected.value?.agent_id, () => {
  hostRemoteFsDrives.value = []
  hostRemoteFsRoots.value = []
  hostRemoteFsEntries.value = []
  hostRemoteFsPreview.value = ''
  hostRemoteFsHint.value = ''
  hostLiveQueryRows.value = []
  hostLiveQueryMeta.value = null
  if (hostTabGroup.value === 'remote' && hostRemoteSubTab.value === 'files' && selected.value?.online) {
    hostRemoteFsLoadVolumes()
  }
})

onMounted(async () => {
  restoreNavState()
  hydrateEventsCache() // 刷新瞬间先用缓存顶住威胁列表，避免空白
  await refresh()
  if (pendingThreatRestoreId.value) {
    const tid = pendingThreatRestoreId.value
    pendingThreatRestoreId.value = null
    section.value = 'detect'
    try { await openEventById(tid) } catch { /* ignore */ }
  }
  loadTags()
  loadInvLocal()
  // SSE 推送静默合并；断线兜底软刷新（勿与重晋升叠堵）
  stopStream = subscribeAgentStream((msg) => {
    liveOk.value = true
    const kind = msg?.kind || ''
    const rulesKind = kind === 'policy' || kind === 'rules' || kind === 'whitelist' || kind === 'ioc' || kind === 'command'
    const fleetKind = kind === 'register' || kind === 'agent' || kind === 'heartbeat' || kind === 'agent_deleted'
    if (page.value === 'rules' && shouldRefreshAgentSyncManifest(kind)) {
      loadAgentSyncManifest({ silent: true })
    }
    softRefresh({
      snap: kind === 'snapshot' || kind === 'event' || kind === 'timeline',
      rules: rulesKind,
      overview: fleetKind || page.value === 'overview',
      events: kind === 'event', // 有新告警才立刻刷新列表
    })
  })
  const softRefreshTick = () => {
    softRefresh({
      snap: !!(selected.value && (page.value === 'hosts' || page.value === 'assets')),
      rules: false,
      overview: page.value === 'overview',
      events: false,
    })
  }
  timer = setInterval(softRefreshTick, 8000)
  liveTickTimer = setInterval(() => {
    nowTick.value = Date.now()
  }, 1000)
  document.addEventListener('click', closeUserMenu)
})
onUnmounted(() => {
  document.removeEventListener('click', closeUserMenu)
  if (timer) clearInterval(timer)
  if (overviewReloadTimer) clearTimeout(overviewReloadTimer)
  if (snapTimer) clearInterval(snapTimer)
  if (liveTickTimer) clearInterval(liveTickTimer)
  if (respPollTimer) clearInterval(respPollTimer)
  try { stopStream?.() } catch { /* ignore */ }
})
</script>

<style scoped>
.app {
  display: grid;
  grid-template-columns: 76px 1fr;
  height: 100%;
  min-height: 100vh;
  position: relative;
}
.rail {
  background: linear-gradient(180deg, #0a101c 0%, #121a2a 55%, #0f1624 100%);
  color: #8b9cb3;
  display: flex;
  flex-direction: column;
  padding: 12px 8px 14px;
  border-right: 1px solid rgba(255,255,255,.04);
}
.logo {
  display: flex; flex-direction: column; align-items: center; gap: 8px;
  padding: 8px 4px 18px; color: #fff;
  border-bottom: 1px solid rgba(255,255,255,.06);
  margin-bottom: 10px;
}
.logo-mark {
  width: 36px; height: 36px; border-radius: 10px;
  background: linear-gradient(145deg, #c81626 0%, #a8121f 100%);
  box-shadow: 0 6px 16px rgba(200, 22, 38, .35);
  display: grid; place-items: center; font-weight: 750; font-size: 15px;
  letter-spacing: -.02em;
}
.logo-name {
  font-size: 12px; font-weight: 700; letter-spacing: .04em;
  color: #e8eef8; line-height: 1;
}
.rail-nav { display: flex; flex-direction: column; gap: 4px; flex: 1; }
.rail-item {
  position: relative; border: 0; background: transparent; color: inherit;
  border-radius: 12px; padding: 10px 4px 9px; text-align: center;
  display: flex; flex-direction: column; gap: 5px; align-items: center;
  transition: background .15s, color .15s;
}
.rail-item::before {
  content: ''; position: absolute; left: -8px; top: 50%; transform: translateY(-50%);
  width: 3px; height: 0; border-radius: 0 3px 3px 0; background: #e11d2e;
  transition: height .15s;
}
.rail-item:hover { background: rgba(255,255,255,.05); color: #dbe7f7; }
.rail-item.on {
  background: rgba(200, 22, 38, .22); color: #fff;
  box-shadow: inset 0 0 0 1px rgba(200, 22, 38, .28);
}
.rail-item.on::before { height: 22px; }
.rail-item .ico {
  display: grid; place-items: center; width: 24px; height: 24px; opacity: .88;
}
.rail-item.on .ico { opacity: 1; color: #fecaca; }
.rail-item em {
  font-style: normal; font-size: 11px; font-weight: 600;
  letter-spacing: .02em; line-height: 1.1; white-space: nowrap;
}
.dot-n {
  position: absolute; top: 4px; right: 4px; min-width: 16px; height: 16px;
  padding: 0 4px; border-radius: 999px; background: #f97316; color: #fff;
  font-size: 10px; font-style: normal; font-weight: 700;
  display: grid; place-items: center; box-shadow: 0 0 0 2px #0f1624;
}
.rail-bottom {
  position: relative; margin-top: auto; padding-top: 12px;
  border-top: 1px solid rgba(255,255,255,.06); text-align: center;
}
.rail-user {
  width: 100%; border: 0; background: transparent; color: #a9b8cd; border-radius: 12px;
  padding: 8px 4px; display: flex; flex-direction: column; align-items: center; gap: 6px;
}
.rail-user:hover { background: rgba(255,255,255,.05); color: #e8eef8; }
.rail-user em {
  font-style: normal; font-size: 11px; font-weight: 600; max-width: 100%;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ru-avatar {
  width: 30px; height: 30px; border-radius: 50%; display: grid; place-items: center; flex: none;
  background: linear-gradient(145deg, #334155, #1e293b); color: #e2e8f0;
  font-size: 13px; font-weight: 700; box-shadow: inset 0 0 0 1px rgba(255,255,255,.12);
}
.ru-avatar.lg { width: 38px; height: 38px; font-size: 15px; background: linear-gradient(145deg, #3b82f6, #1d4ed8); color: #fff; }
.ru-avatar.sm { width: 28px; height: 28px; font-size: 12px; background: var(--accent-soft); color: var(--accent); box-shadow: none; }
.user-pop {
  position: absolute; left: calc(100% + 10px); bottom: 4px; z-index: 50; width: 230px;
  background: #fff; color: var(--ink); text-align: left; border-radius: 12px; padding: 8px;
  border: 1px solid var(--line); box-shadow: 0 12px 36px rgba(15, 23, 36, .18);
}
.up-head { display: flex; align-items: center; gap: 10px; padding: 8px 8px 10px; border-bottom: 1px solid var(--line-2); }
.up-head strong { display: block; font-size: 14px; }
.up-head small { color: var(--muted); font-size: 12px; }
.up-meta { margin: 8px 8px 4px; font-size: 11px; color: var(--muted); }
.up-item {
  display: block; width: 100%; text-align: left; border: 0; background: transparent;
  padding: 9px 10px; border-radius: 8px; font-size: 13px; color: var(--ink-2);
}
.up-item:hover { background: var(--line-2); color: var(--ink); }
.up-item.danger { color: var(--danger); }
.up-item.danger:hover { background: #fff1f2; }

.acct-table td { vertical-align: middle; }
.acct-name { display: flex; align-items: center; gap: 10px; }
.acct-name strong { display: block; font-size: 13px; }
.acct-name small { color: var(--muted); font-size: 12px; }
.acct-me {
  margin-left: 6px; padding: 0 6px; border-radius: 4px; font-style: normal; font-size: 11px;
  background: var(--accent-soft); color: var(--accent);
}
.acct-ip { display: block; font-size: 11px; color: var(--muted); }
.field.sm { width: auto; min-width: 96px; padding: 5px 8px; margin-top: 0; font-size: 13px; }
.pill.warn { background: #fff4e5; color: #b54708; margin-left: 6px; }

.dlg-mask {
  position: fixed; inset: 0; z-index: 100; background: rgba(15, 23, 36, .45);
  display: grid; place-items: center; padding: 20px;
}
.dlg {
  width: 100%; max-width: 420px; background: #fff; border-radius: 14px; padding: 24px 24px 20px;
  box-shadow: 0 20px 60px rgba(15, 23, 36, .25);
}
.dlg h3 { margin: 0 0 16px; font-size: 17px; }
.dlg label { display: block; margin-bottom: 12px; font-weight: 600; font-size: 13px; }
.dlg-err {
  margin: 4px 0 0; padding: 8px 10px; border-radius: 8px; font-size: 13px;
  background: #fff1f2; color: #be123c;
}
.dlg-ops { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; }
.dlg.allow-dlg { max-width: 600px; max-height: calc(100vh - 40px); overflow: auto; }
.allow-src {
  margin: -6px 0 14px; padding: 8px 10px; border-radius: 8px; background: #f4f6fa;
  font-size: 12.5px; color: #475569; word-break: break-all;
}
.allow-sec { font-weight: 600; font-size: 13px; margin-bottom: 6px; }
.allow-sec-row { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap: wrap; }
.allow-sec-row .allow-sec { margin: 0; flex: 1; }
.ed-prev-hint { margin: 0 0 8px; color: #64748b; }
.ed-beh-row.current { border-left: 3px solid var(--primary, #2563eb); padding-left: 8px; }
.ed-cur-tag { font-style: normal; font-size: 11px; color: #2563eb; margin-left: 6px; font-weight: 600; }
.ed-file-src { display: block; font-size: 11px; color: #64748b; margin-top: 2px; font-style: normal; }
.allow-opts { display: flex; flex-direction: column; gap: 6px; margin-bottom: 14px; max-height: 240px; overflow: auto; }
.dlg label.allow-opt {
  display: grid; grid-template-columns: 20px 92px minmax(0, 1fr); align-items: center; gap: 8px;
  margin: 0; padding: 7px 10px; border: 1px solid #e3e8ef; border-radius: 8px; cursor: pointer;
  font-weight: 400;
}
.dlg label.allow-opt input[type='checkbox'] {
  width: 16px; height: 16px; margin: 0; accent-color: var(--primary, #2563eb);
}
.dlg label.allow-opt.on { border-color: var(--primary, #2563eb); background: #f0f6ff; }
.allow-k { font-size: 12px; color: #64748b; }
.allow-opt code { font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.allow-tip { font-style: normal; font-weight: 400; color: #94a3b8; font-size: 12px; margin-left: 6px; }
.dlg label.chk { display: flex; align-items: flex-start; gap: 6px; font-weight: 400; }
.dlg label.chk input { margin-top: 3px; }
.warn-hint { color: #b45309; }
.wl-val { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
tr.wl-off td { opacity: .5; }

.menu {
  position: fixed; left: 76px; top: 0; bottom: 0; width: 212px; z-index: 45;
  background: #fff; border-right: 1px solid var(--line);
  padding: 16px 12px 20px; overflow: auto;
  box-shadow: 8px 0 28px rgba(15, 23, 42, .08);
  transform: translateX(-12px); opacity: 0; pointer-events: none;
  transition: opacity .16s ease, transform .16s ease;
}
.menu.open {
  opacity: 1; pointer-events: auto; transform: translateX(0);
}
.menu-top {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  margin-bottom: 10px; padding: 0 4px;
}
.menu h2 { margin: 0; font-size: 15px; font-weight: 700; }
.menu-pin {
  border: 1px solid var(--line); background: #fff; border-radius: 999px;
  padding: 3px 9px; font-size: 11px; font-weight: 650; color: var(--muted); cursor: pointer;
}
.menu-pin.on { border-color: #93c5fd; background: #eff6ff; color: #1d4ed8; }
.menu-group {
  margin: 14px 12px 6px; font-size: 11px; font-weight: 700; color: #98a2b3;
  letter-spacing: .04em;
}
.menu-item {
  width: 100%; text-align: left; border: 0; background: transparent;
  border-radius: 8px; padding: 9px 12px; color: var(--ink-2); font-size: 13px; font-weight: 500;
}
.menu-item:hover { background: var(--line-2); }
.menu-item.on { background: var(--accent-soft); color: var(--accent); font-weight: 650; }
.menu-hint {
  margin-top: 18px; padding: 10px 12px; border-radius: 8px;
  background: #f7f9fc; color: var(--muted); font-size: 11px; line-height: 1.55;
}
.menu-hint.soft { background: #f8fafc; border: 1px dashed #e4e7ec; }

.workspace {
  min-width: 0; height: 100vh;
  overflow: hidden; /* 禁止整页右侧下拉，各 page 内部自己滚 */
  display: flex; flex-direction: column;
  background: var(--bg); transition: padding-left .16s ease;
}
.workspace.menu-pinned { padding-left: 212px; }
.page {
  padding: 20px 24px 12px; box-sizing: border-box;
  flex: 1; min-height: 0;
  display: flex; flex-direction: column;
  overflow: hidden; /* 结构化页面：只让表格/列表区滚动 */
}
/* 无专用布局的表单/列表页：允许页内滚动（仍只有一条滚动条） */
.page:not(.overview):not(.events-page):not(.behaviors-page):not(.timeline-page):not(.rules-page):not(.settings-page):not(.inv-page):not(.host-detail):not(.threat-detail):not(.attck-page):not(.hosts-page):not(.seq-page):not(.dns-page):not(.ai-page) {
  overflow: auto;
}
/* 概览：撑满可视区，底部面板吃掉剩余高度 */
.page.overview {
  overflow: auto;
  padding-bottom: 12px;
}
.page-hd {
  display: flex; justify-content: space-between; align-items: flex-start;
  gap: 16px; margin-bottom: 16px;
  background: #fff;
  border: 1px solid rgba(15, 23, 42, .06);
  border-radius: 14px;
  padding: 16px 20px;
  box-shadow: 0 8px 24px rgba(15, 23, 42, .045);
}
.page-hd h1 { margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -.02em; }
.desc { margin: 5px 0 0; color: var(--muted); font-size: 13px; }
.hd-right { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.sync-pill {
  display: inline-flex; align-items: center; gap: 6px;
  border: 1px solid var(--line); background: #fff; border-radius: 999px;
  padding: 6px 12px; font-size: 12px; color: var(--muted); font-weight: 600;
}
.sync-pill.on { border-color: #a7f3d0; background: #ecfdf5; color: #047857; }
.sync-dot {
  width: 7px; height: 7px; border-radius: 50%; background: #c5ccd8;
}
.sync-pill.on .sync-dot {
  background: var(--online);
  box-shadow: 0 0 0 3px rgba(18,183,106,.2);
  animation: pulse 1.4s ease infinite;
}
@keyframes pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(18,183,106,.35); }
  50% { box-shadow: 0 0 0 5px rgba(18,183,106,0); }
}

.btn {
  border: 1px solid var(--line); background: #fff; border-radius: 8px;
  padding: 7px 13px; font-size: 13px; font-weight: 550; color: var(--ink-2);
}
.btn:hover { border-color: #cfd7e6; }
.btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.btn.primary.lg { padding: 11px 16px; font-size: 14px; margin-top: 12px; }
.btn.danger { color: var(--danger); border-color: #f3c1c5; background: #fff7f8; }
.btn.danger-outline { color: #c2410c; border-color: #fdba74; background: #fff7ed; }
.btn-text { border: 0; background: none; color: var(--accent); font-weight: 600; font-size: 13px; }

.ov-fleet-strip {
  display: flex; align-items: stretch; gap: 10px; margin-bottom: 12px;
  background: linear-gradient(135deg, #1a2332 0%, #243044 55%, #1e293b 100%);
  border-radius: 14px; padding: 14px 16px; color: #e8edf5;
  box-shadow: 0 12px 32px rgba(15, 23, 42, .18);
}
.ov-fleet-strip.collapsed .ov-fleet-main { display: none; }
.ov-fleet-main { display: flex; flex: 1; gap: 18px; align-items: stretch; min-width: 0; }
.ov-fleet-block { flex: 1; min-width: 0; }
.ov-fleet-block:last-child { flex: 1.15; }
.ov-fleet-hd { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #94a3b8; margin-bottom: 8px; }
.ov-fleet-ico { font-size: 16px; opacity: .85; }
.ov-info { font-style: normal; font-size: 11px; width: 16px; height: 16px; border-radius: 50%; border: 1px solid #64748b; display: inline-grid; place-items: center; cursor: help; }
.ov-fleet-metric { display: flex; align-items: baseline; gap: 10px; margin-bottom: 10px; }
.ov-fleet-metric > strong { font-size: 28px; font-weight: 700; letter-spacing: -.02em; }
.ov-pill { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px; }
.ov-pill.agent { background: #2563eb; color: #fff; }
.ov-pill.va { background: #ea580c; color: #fff; }
.ov-fleet-div { width: 1px; background: rgba(148, 163, 184, .25); align-self: stretch; }
.ov-fleet-sub { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 20px; align-items: end; }
.ov-fleet-sub.three {
  display: flex;
  flex-wrap: wrap;
  gap: 12px 28px;
  align-items: flex-end;
  justify-content: flex-start;
}
.ov-fleet-sub.three .ov-fleet-cell { flex: 0 1 auto; min-width: 7.5rem; max-width: 14rem; }
.ov-fleet-cell em { display: block; font-style: normal; font-size: 12px; color: #94a3b8; margin-bottom: 4px; }
.ov-fleet-cell b { font-size: 20px; font-weight: 700; }
.ov-fleet-cell.click { cursor: pointer; border-radius: 8px; padding: 4px 6px; margin: -4px -6px; }
.ov-fleet-cell.click:hover { background: rgba(255,255,255,.06); }
.ov-spark-row { display: flex; align-items: center; gap: 10px; }
.ov-spark { width: 120px; height: 32px; flex-shrink: 0; opacity: .95; }
.ov-fleet-toggle {
  align-self: center; border: 1px solid rgba(148,163,184,.35); background: transparent; color: #cbd5e1;
  border-radius: 8px; padding: 6px 10px; font-size: 12px; cursor: pointer;
}
.ov-threat-rail {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px;
}
.ov-rail-card {
  display: flex; gap: 12px; align-items: center; padding: 14px 16px; border-radius: 12px;
  background: #fff; border: 1px solid rgba(15, 23, 42, .08);
  box-shadow: 0 6px 18px rgba(15, 23, 42, .05);
}
.ov-rail-card.click { cursor: pointer; transition: border-color .15s, box-shadow .15s; }
.ov-rail-card.click:hover { border-color: #93c5fd; box-shadow: 0 8px 22px rgba(37, 99, 235, .12); }
.ov-rail-ico { width: 40px; height: 40px; border-radius: 10px; display: grid; place-items: center; font-size: 18px; background: #f1f5f9; flex-shrink: 0; }
.ov-rail-ico.warn { background: #fee2e2; color: #b91c1c; }
.ov-rail-body span { display: block; font-size: 12px; color: var(--muted); }
.ov-rail-body strong { font-size: 22px; font-weight: 800; line-height: 1.2; }
.ov-rail-body small { font-size: 11px; color: var(--muted); }
.ov-rail-body small b.ok { color: #059669; }
.ov-bottom-grid {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px;
  margin-top: 12px; flex: 0 0 auto;
}
.ov-panel { min-height: 168px; display: flex; flex-direction: column; }
.ov-panel .ov-bars, .ov-panel .ov-trend, .ov-panel .ov-rank, .ov-panel .ov-mal-list { flex: 1; }
.ov-cats-compact { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.ov-mal-list.compact { padding: 6px 14px 12px; }
.ov-ops-mini {
  margin: 0 12px 10px; padding: 10px 12px; border-radius: 10px;
  background: #f8fafc; border: 1px solid var(--line);
}
.ov-ops-hd { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; font-size: 13px; }
.ov-ops-dl { display: grid; grid-template-columns: 1fr; gap: 6px; margin: 0; font-size: 12px; }
.ov-ops-dl div { display: flex; justify-content: space-between; gap: 8px; }
.ov-ops-dl dt { color: var(--muted); margin: 0; }
.ov-ops-dl dd { margin: 0; font-weight: 600; text-align: right; }
.ov-cap-hint { margin: 8px 0 0; line-height: 1.45; }
.ov-mal-list { list-style: none; margin: 0; padding: 8px 16px 14px; }
.ov-mal-list li { display: grid; grid-template-columns: 24px 1fr auto; gap: 10px; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--line); font-size: 13px; }
.ov-mal-list li:last-child { border-bottom: 0; }
.ov-mal-list i { font-style: normal; color: var(--muted); font-weight: 700; }
.ov-mal-list em { font-style: normal; font-weight: 700; }
.comp-health .hchip.off { opacity: .55; }
.capture-hint-line { margin: 6px 0 0; }

.ov-kpis {
  display: grid; grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px; margin-bottom: 14px;
}
.ov-kpis-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.ov-quick { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
.overview { display: flex; flex-direction: column; gap: 0; min-height: 0; flex: 1; }
.ov-body {
  display: grid; grid-template-columns: minmax(0, 1.7fr) minmax(280px, .85fr);
  gap: 14px; align-items: stretch; flex: 1 1 auto; min-height: 0;
}
.ov-threats { min-width: 0; display: flex; flex-direction: column; min-height: 0; }
.ov-threats .ov-threat-scroll { flex: 1; min-height: 0; max-height: none; }
.ov-start { margin-top: 14px; flex: 0 0 auto; }
.ov-steps { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; padding: 14px 16px 16px; }
.ov-step {
  display: grid; grid-template-columns: 30px 1fr; grid-template-rows: auto auto; column-gap: 10px; row-gap: 4px;
  text-align: left; border: 1px dashed #c9d4ea; background: #f8faff; border-radius: 10px; padding: 12px; cursor: pointer;
}
.ov-step:hover { border-color: var(--accent); background: var(--accent-soft); }
.ov-step i {
  grid-row: span 2; width: 30px; height: 30px; border-radius: 50%; background: var(--accent); color: #fff;
  display: grid; place-items: center; font-style: normal; font-weight: 700;
}
.ov-step b { font-size: 13px; }
.ov-step small { color: var(--muted); font-size: 12px; line-height: 1.5; }
.ov-grid3 {
  display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
  grid-auto-rows: minmax(160px, 1fr);
  gap: 14px; margin-top: 14px; margin-bottom: 0;
  align-items: stretch; flex: 1 1 auto; min-height: 0;
}
.ov-grid3 > .panel { min-width: 0; min-height: 0; display: flex; flex-direction: column; height: 100%; }
.ov-span2 { grid-column: span 2; }
.ov-cats { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 6px; padding: 12px 14px 14px; }
.ov-cat {
  display: flex; align-items: center; gap: 8px; border: 1px solid var(--line); background: #fafbfd;
  border-radius: 8px; padding: 7px 9px; cursor: pointer; text-align: left; min-width: 0;
}
.ov-cat:hover { border-color: #b7c9f0; background: var(--accent-soft); }
.ov-cat .focus-ico { width: 24px; height: 24px; font-size: 11px; }
.ov-cat b { flex: 1; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ov-cat em { font-style: normal; font-weight: 700; font-size: 13px; }
.ov-bars { display: flex; flex-direction: column; gap: 12px; padding: 16px; flex: 1; justify-content: center; }
.ov-bar-row { display: grid; grid-template-columns: 48px 1fr 40px; align-items: center; gap: 10px; }
.ov-bar-row b { text-align: right; font-size: 13px; }
.ov-bar { height: 8px; border-radius: 4px; background: #eef1f6; overflow: hidden; }
.ov-bar i { display: block; height: 100%; border-radius: 4px; background: #98a2b3; transition: width .3s; }
.ov-bar i[data-s="critical"] { background: #b42318; }
.ov-bar i[data-s="high"] { background: #e11d2e; }
.ov-bar i[data-s="medium"] { background: #f79009; }
.ov-bar i[data-s="low"] { background: #2e90fa; }
.ov-trend { display: grid; grid-template-columns: repeat(7, 1fr); gap: 8px; padding: 14px 16px 12px; flex: 1; min-height: 170px; }
.ov-trend-col { display: flex; flex-direction: column; align-items: center; gap: 4px; min-width: 0; }
.ov-trend-col em { font-style: normal; font-size: 11px; color: var(--muted); height: 14px; }
.ov-trend-bar { position: relative; flex: 1; width: 100%; max-width: 30px; background: #f2f4f8; border-radius: 6px; overflow: hidden; }
.ov-trend-bar i { position: absolute; left: 0; right: 0; bottom: 0; background: #9db4e6; border-radius: 6px 6px 0 0; }
.ov-trend-bar i.hi { background: #e11d2e; opacity: .85; }
.ov-trend-col small { font-size: 11px; color: var(--muted); }
.ov-rank { display: flex; flex-direction: column; gap: 4px; padding: 10px 12px 12px; }
.ov-rank-row {
  display: grid; grid-template-columns: 22px 1fr auto auto; align-items: center; gap: 8px;
  border: 0; background: transparent; border-radius: 8px; padding: 8px; cursor: pointer; text-align: left;
}
.ov-rank-row:hover { background: var(--accent-soft); }
.ov-rank-row i {
  font-style: normal; width: 22px; height: 22px; border-radius: 6px; background: #eef1f6;
  display: grid; place-items: center; font-size: 12px; font-weight: 700;
}
.ov-rank-row:nth-child(-n+3) i { background: #fde8e8; color: #b42318; }
.ov-rank-row b { font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ov-rank-row em { font-style: normal; color: var(--muted); font-size: 12px; }
.ov-tactics { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 8px; padding: 14px 16px 16px; }
.ov-tactic {
  border: 1px solid var(--line); border-radius: 8px; padding: 10px; background: #fafbfd;
  display: flex; justify-content: space-between; align-items: center; gap: 6px;
}
.ov-tactic b { font-size: 12px; font-weight: 600; color: var(--muted); }
.ov-tactic em { font-style: normal; font-weight: 700; color: #98a2b3; }
.ov-tactic.on { border-color: #f5c2c2; background: #fff5f5; }
.ov-tactic.on b { color: var(--ink, #1d2939); }
.ov-tactic.on em { color: #b42318; }
@media (max-width: 1280px) {
  .ov-bottom-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ov-threat-rail { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ov-cats-compact { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 900px) {
  .ov-bottom-grid, .ov-threat-rail { grid-template-columns: 1fr; }
  .ov-fleet-sub.three { flex-direction: column; align-items: stretch; }
  .ov-fleet-sub.three .ov-fleet-cell { max-width: none; }
  .ov-body { grid-template-columns: 1fr; }
}
.ov-threat-scroll { max-height: min(520px, calc(100vh - 260px)); }
.ov-side { display: flex; flex-direction: column; min-width: 0; min-height: 0; height: 100%; }
.ov-host-summary {
  display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px;
  padding: 10px 12px; border-bottom: 1px solid var(--line); flex-shrink: 0;
}
.ov-host-summary > div {
  background: #f7f9fc; border-radius: 8px; padding: 8px 10px; text-align: center;
}
.ov-host-summary b { display: block; font-size: 18px; font-weight: 700; color: var(--ink); line-height: 1.2; }
.ov-host-summary span { font-size: 11px; color: var(--muted); }
.ov-host-list {
  padding: 6px 8px; display: flex; flex-direction: column; gap: 2px;
  flex: 1 1 auto; min-height: 0; overflow: auto;
}
.ov-host-row {
  display: flex; align-items: center; gap: 10px; width: 100%; text-align: left;
  border: 0; background: transparent; border-radius: 8px; padding: 9px 10px; cursor: pointer;
}
.ov-host-row:hover { background: #f5f8fc; }
.ov-host-main { flex: 1; min-width: 0; }
.ov-host-main b {
  display: block; font-size: 13px; font-weight: 650;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ov-host-main small { color: var(--muted); font-size: 11px; }
.ov-host-ok { font-size: 11px; color: #059669; font-weight: 600; flex-shrink: 0; }
.ov-side-links {
  display: flex; flex-wrap: wrap; gap: 8px; padding: 12px 14px 14px;
  border-top: 1px solid var(--line); margin-top: auto; flex-shrink: 0;
}
.kpi {
  background: #fff; border: 1px solid rgba(15, 23, 42, .06); border-radius: 12px;
  padding: 16px 18px 14px; box-shadow: 0 6px 18px rgba(15, 23, 42, .04);
  transition: box-shadow .15s, transform .15s, border-color .15s;
}
.kpi.compact { padding: 14px 16px 12px; }
.kpi.compact strong { font-size: 28px; }
.kpi.compact strong small {
  font-size: 15px; font-weight: 600; color: #98a2b3; margin-left: 2px; letter-spacing: 0;
}
.kpi.compact span { margin-bottom: 6px; }
.kpi.compact em { display: none; }
.kpi span { display: block; color: #98a2b3; font-size: 13px; font-weight: 500; margin-bottom: 10px; }
.kpi strong { display: block; font-size: 38px; font-weight: 720; letter-spacing: -.04em; line-height: 1.05; color: var(--ink); }
.kpi em { display: block; margin-top: 10px; font-style: normal; color: #98a2b3; font-size: 12px; }
.kpi.click { cursor: pointer; }
.kpi.click:hover {
  border-color: rgba(37, 99, 235, .22);
  box-shadow: 0 12px 28px rgba(15, 23, 42, .07);
  transform: translateY(-1px);
}
.c-online { color: #12b76a; }
.c-offline { color: #667085; }
.c-danger { color: #f04438; }
.c-ink { color: #101828; }
.live-hint {
  display: inline-flex; align-items: center; gap: 7px;
  font-size: 12px; color: var(--muted); font-weight: 550;
  padding: 6px 10px; border-radius: 999px; background: #f2f4f7;
}
.live-hint.on { color: #027a48; background: #ecfdf3; }
.live-dot {
  width: 7px; height: 7px; border-radius: 50%; background: #98a2b3;
  display: inline-block;
}
.live-hint.on .live-dot { background: #12b76a; box-shadow: 0 0 0 3px rgba(18, 183, 106, .18); }
.btn.ghost-btn {
  background: #fff; color: var(--ink-2); border-color: var(--line);
  box-shadow: none;
}

.ov-grid {
  display: grid; grid-template-columns: 1.25fr .85fr; gap: 16px;
  min-height: 0;
  align-items: start;
}
.ov-panel { border-color: rgba(15, 23, 42, .06); box-shadow: 0 8px 24px rgba(15, 23, 42, .04); }
.ov-threat-table { overflow: auto; flex: 1; padding: 10px 12px 14px; display: flex; flex-direction: column; gap: 8px; }
.ov-threat-row {
  width: 100%; display: flex; align-items: center; gap: 12px; text-align: left;
  border: 1px solid transparent; background: #fafbfc;
  padding: 12px 14px; border-radius: 10px;
}
.ov-threat-row.cardish:hover { background: #f4f7fb; border-color: #e4eaf3; }
.ot-main { flex: 1; min-width: 0; }
.ot-main b { display: block; font-size: 13px; font-weight: 650; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ot-main small { color: var(--muted); font-size: 11px; }
.ot-go { flex-shrink: 0; color: var(--accent); font-size: 12px; font-weight: 650; }

.settings-page {
  overflow: hidden;
  padding-bottom: 12px;
}
.settings-page > .page-hd { flex-shrink: 0; }
.settings-stack {
  flex: 1; min-height: 0; display: flex; flex-direction: column; gap: 12px;
}
.settings-addr { flex-shrink: 0; }
.settings-addr-row {
  display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap;
}
.settings-addr-row .grow { flex: 1; min-width: 240px; }
.settings-addr-acts { display: flex; gap: 8px; padding-bottom: 2px; }
.settings-rules-panel {
  flex: 1; min-height: 0; display: flex; flex-direction: column;
}
.settings-rules-panel > .panel-hd { flex-shrink: 0; }
.settings-rules-empty { padding: 48px 16px; text-align: center; }
.settings-rules-panel .settings-rules-table {
  flex: 1; min-height: 0; max-height: none; height: auto;
  border: 0; border-radius: 0; border-top: 1px solid var(--line);
}
.btn.ghost { background: transparent; border-color: transparent; color: var(--accent); box-shadow: none; }
.host-cards.padded { padding: 10px 12px 14px; display: flex; flex-direction: column; gap: 8px; }
.host-card.rich {
  flex-direction: column; align-items: stretch; gap: 6px; padding: 12px 14px;
  border-bottom: 1px solid var(--line); border-radius: 0;
}
.host-card.rich.tile {
  border: 1px solid #eef1f6; border-radius: 12px; border-bottom-color: #eef1f6;
  background: #fafbfc; box-shadow: none;
}
.host-card.rich.tile:hover { background: #f4f7fb; border-color: #dde5f0; }
.host-card.rich:last-of-type { border-bottom: 0; }
.host-card.rich.tile:last-of-type { border-bottom: 1px solid #eef1f6; }
.hc-top { display: flex; align-items: center; gap: 8px; }
.hc-top b { flex: 1; font-size: 13px; text-align: left; }
.hc-meta {
  display: flex; flex-wrap: wrap; gap: 8px 12px; font-size: 11px; color: var(--muted); padding-left: 16px;
}
.hc-act { padding-left: 16px; font-size: 12px; color: var(--accent); font-weight: 600; text-align: left; }
.alert-n.badge {
  min-width: 18px; height: 18px; padding: 0 5px; border-radius: 999px;
  display: inline-grid; place-items: center; font-size: 11px; font-style: normal;
}
.child-list { display: flex; flex-direction: column; gap: 4px; margin-top: 8px; }
.child-list > small { color: var(--muted); font-size: 11px; }
.child-row {
  display: flex; justify-content: space-between; gap: 8px; text-align: left;
  border: 1px solid var(--line); background: #fafbfd; border-radius: 8px;
  padding: 6px 10px; font-size: 12px; cursor: pointer;
}
.child-row:hover { border-color: #b7c9f0; background: #f4f7fb; }
.child-row em { color: var(--muted); font-style: normal; }
.evt-table th.chk, .evt-table td.chk { width: 36px; text-align: center; }
.evt-table th.sortable { cursor: pointer; user-select: none; }
.evt-table th.sortable:hover { color: var(--ink); }
.sort-ico { font-style: normal; color: #98a2b3; font-size: 11px; margin-left: 2px; }
.tag.judge { background: #eef2ff; color: #3730a3; border-radius: 999px; padding: 2px 10px; }
.log-n {
  display: inline-flex; min-width: 26px; justify-content: center; align-items: center;
  padding: 2px 9px; border-radius: 999px; background: #f2f4f7; color: #475467;
  font-weight: 700; font-size: 12px; font-variant-numeric: tabular-nums;
  border: 1px solid transparent; cursor: pointer; font-family: inherit;
}
.log-n:hover { filter: brightness(0.96); outline: 2px solid rgba(37, 99, 235, 0.25); }
.log-n.hot {
  background: #fff7ed; color: #c2410c; border-color: #fdba74;
}
.log-n.multi {
  background: #fef2f2; color: #b91c1c; border-color: #fca5a5;
  box-shadow: 0 0 0 2px rgba(248, 113, 113, 0.15);
}
.sev-filter { min-width: 110px; }
.evt-filter-bar {
  display: flex; flex-wrap: wrap; gap: 10px 12px; align-items: flex-end;
  margin: 0 0 12px; padding: 12px 14px;
}
.evt-fl {
  display: flex; flex-direction: column; gap: 4px; min-width: 140px;
}
.evt-fl.grow { flex: 1 1 200px; min-width: 200px; }
.evt-fl > span {
  font-size: 12px; color: var(--muted); font-weight: 600;
}
.evt-fl .field { min-width: 140px; }
.evt-fl-acts {
  display: flex; gap: 8px; align-items: center; padding-bottom: 1px;
}
.evt-fl.chk-inline { min-width: 220px; }
.dns-checks { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; min-height: 34px; }
.dns-summary {
  display: flex; flex-wrap: wrap; gap: 16px 24px; align-items: center;
  margin: 0 0 12px; flex-shrink: 0;
}
.dns-summary .mal-stat { min-width: 88px; }
.dns-summary .hint { margin: 0; flex: 1 1 200px; }
.dns-summary .hint .off { color: var(--danger); font-weight: 600; }
.dns-summary .hint code { font-size: 11px; }
/* DNS：表头/筛选固定，表格区滚动，底部分页始终可见 */
.dns-page { overflow: hidden; }
.dns-page > .page-hd { flex-shrink: 0; margin-bottom: 10px; }
.dns-page > .evt-filter-bar { flex-shrink: 0; margin-bottom: 10px; }
.dns-page > .dns-summary { flex-shrink: 0; }
.dns-table-panel {
  flex: 1 1 auto; min-height: 0;
  display: flex; flex-direction: column;
  overflow: hidden; margin: 0;
}
.dns-table-scroll {
  flex: 1 1 auto; min-height: 0; overflow: auto;
}
.dns-pager {
  flex-shrink: 0;
  margin-top: 10px;
  padding-top: 8px;
  border-top: 1px solid var(--line);
  background: #fff;
}
.hunt-bar { display: flex; gap: 8px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
.hunt-bar .grow, .search.grow { flex: 1; min-width: 180px; }
.hunt-quick { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.chip {
  border: 1px solid var(--line); background: #fff; border-radius: 999px;
  padding: 5px 12px; font-size: 12px; color: var(--ink-2); cursor: pointer;
}
.chip:hover { border-color: #b7c9f0; color: var(--accent); }
.timeline-page {
  overflow: hidden;
  gap: 0;
}
.tl-filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; flex-shrink: 0; }
.tl-hint { flex-shrink: 0; margin: 0 0 12px; font-size: 12px; color: var(--muted); }
.tl-fchip {
  border: 1px solid #e4eaf3; background: #fff; border-radius: 999px;
  padding: 6px 12px; font-size: 12px; color: var(--ink-2); cursor: pointer;
  display: inline-flex; align-items: center; gap: 6px;
}
.tl-fchip em {
  font-style: normal; font-size: 11px; font-weight: 700; color: #98a2b3;
  background: #f2f4f7; border-radius: 999px; padding: 0 6px; min-width: 18px; text-align: center;
}
.tl-fchip.on { border-color: #93c5fd; background: #eff6ff; color: #1d4ed8; }
.tl-fchip.on em { background: #dbeafe; color: #1d4ed8; }
.tl-fchip[data-k="file"].on { border-color: #f9a8d4; background: #fdf2f8; color: #9d174d; }
.tl-fchip[data-k="proc"].on { border-color: #86efac; background: #f0fdf4; color: #166534; }
.tl-fchip[data-k="exit"].on { border-color: #cbd5e1; background: #f8fafc; color: #475569; }
.tl-board {
  flex: 1; min-height: 0; overflow: hidden;
  display: flex; flex-direction: column;
  background: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%);
  border: 1px solid #e8eef6; border-radius: 14px;
}
.tl-rail { flex: 1; min-height: 0; overflow: auto; padding: 16px 18px 8px; }
.tl-pager {
  margin: 0; border-radius: 0 0 13px 13px; border-left: 0; border-right: 0; border-bottom: 0;
  background: rgba(255, 255, 255, .92); backdrop-filter: blur(6px);
}
.tl-card {
  display: grid; grid-template-columns: 28px minmax(0, 1fr); gap: 0 12px;
  margin-bottom: 2px;
}
.tl-axis { display: flex; flex-direction: column; align-items: center; padding-top: 14px; }
.tl-dot {
  width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0;
  background: #94a3b8; box-shadow: 0 0 0 3px #e2e8f0; z-index: 1;
}
.tl-card[data-k="proc"] .tl-dot { background: #22c55e; box-shadow: 0 0 0 3px #dcfce7; }
.tl-card[data-k="file"] .tl-dot { background: #ec4899; box-shadow: 0 0 0 3px #fce7f3; }
.tl-card[data-k="exit"] .tl-dot { background: #64748b; box-shadow: 0 0 0 3px #e2e8f0; }
.tl-card[data-k="net"] .tl-dot { background: #3b82f6; box-shadow: 0 0 0 3px #dbeafe; }
.tl-card[data-s="high"] .tl-dot,
.tl-card[data-s="critical"] .tl-dot { background: #f04438; box-shadow: 0 0 0 3px #fee4e2; }
.tl-line {
  flex: 1; width: 2px; min-height: 18px; margin-top: 4px;
  background: #e2e8f0; border-radius: 1px;
}
.tl-card:last-child .tl-line { display: none; }
.tl-main {
  background: #fff; border: 1px solid #e8eef6; border-radius: 12px;
  padding: 12px 14px 12px; margin-bottom: 10px; cursor: pointer;
  box-shadow: 0 1px 2px rgba(15, 23, 42, .03);
  transition: border-color .15s, box-shadow .15s;
}
.tl-main:hover { border-color: #c7d7f0; box-shadow: 0 6px 16px rgba(15, 23, 42, .05); }
.tl-card.open .tl-main { border-color: #93c5fd; box-shadow: 0 8px 20px rgba(37, 99, 235, .08); }
.tl-card-hd {
  display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 6px;
}
.tl-card-hd time {
  font-size: 12px; font-weight: 600; color: #667085;
  font-variant-numeric: tabular-nums; min-width: 132px;
}
.tl-etype {
  font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 6px;
  background: #f1f5f9; color: #475569;
}
.tl-etype[data-k="proc"] { background: #dcfce7; color: #166534; }
.tl-etype[data-k="file"] { background: #fce7f3; color: #9d174d; }
.tl-etype[data-k="exit"] { background: #e2e8f0; color: #334155; }
.tl-etype[data-k="net"] { background: #dbeafe; color: #1d4ed8; }
.tl-etype[data-k="alert"] { background: #fee2e2; color: #b91c1c; }
.tl-host { font-size: 11px; color: #98a2b3; margin-right: auto; }
.tl-expand {
  border: 0; background: transparent; color: var(--accent); font-size: 12px;
  font-weight: 650; cursor: pointer; padding: 2px 4px;
}
.tl-title {
  margin: 0; font-size: 14px; font-weight: 650; color: var(--ink);
  line-height: 1.35; word-break: break-word;
}
.tl-preview {
  display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px;
}
.tl-chip {
  display: inline-flex; align-items: baseline; gap: 4px; max-width: 100%;
  padding: 3px 8px; border-radius: 6px; background: #f8fafc; border: 1px solid #eef2f7;
  font-size: 11px; color: var(--ink-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.tl-chip em { font-style: normal; color: #98a2b3; font-weight: 600; }
.tl-fields {
  display: flex; flex-direction: column; gap: 12px;
  margin-top: 12px; padding-top: 12px; border-top: 1px dashed #e8eef6;
}
.tl-g h5 {
  margin: 0 0 8px; font-size: 12px; font-weight: 700; color: #667085; letter-spacing: .02em;
  display: flex; align-items: center; gap: 8px;
}
.tl-g h5 em {
  font-style: normal; font-size: 11px; font-weight: 600; color: #98a2b3;
  background: #f1f5f9; padding: 1px 7px; border-radius: 999px;
}
.tl-g-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px;
}
.tl-raw {
  margin-top: 4px; border: 1px solid #e8eef6; border-radius: 8px; background: #fafbfd;
}
.tl-raw summary {
  cursor: pointer; padding: 8px 12px; font-size: 12px; font-weight: 650; color: var(--muted);
  list-style: none;
}
.tl-raw summary::-webkit-details-marker { display: none; }
.tl-raw[open] summary { border-bottom: 1px solid #e8eef6; color: var(--ink-2); }
.tl-raw pre {
  margin: 0; padding: 10px 12px; max-height: 220px; overflow: auto;
  font-family: ui-monospace, Consolas, monospace; font-size: 11px; line-height: 1.45;
  white-space: pre-wrap; word-break: break-all; color: var(--ink-2);
}
.tl-field {
  background: #f5f8fc; border: 1px solid #e8eef6; border-radius: 8px; padding: 8px 10px; min-width: 0;
}
.tl-field.wide { grid-column: 1 / -1; }
.tl-field label {
  display: block; font-size: 11px; color: #98a2b3; font-weight: 600; margin-bottom: 3px;
}
.tl-fv {
  display: flex; align-items: flex-start; gap: 8px; justify-content: space-between;
}
.tl-fv > span {
  flex: 1; min-width: 0; font-size: 12px; color: var(--ink); word-break: break-all; line-height: 1.45;
}
.tl-fv > span.mono { font-family: ui-monospace, Consolas, monospace; font-size: 11.5px; }
.tl-empty { margin: 0; font-size: 12px; color: var(--muted); }
.tl-acts { display: flex; flex-wrap: wrap; gap: 8px; padding-top: 4px; }
.chk { display: flex !important; align-items: center; gap: 8px; margin: 8px 0; font-weight: 500; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.panel {
  background: #fff; border: 1px solid var(--line); border-radius: 12px;
  box-shadow: var(--shadow); overflow: hidden;
}
.panel.fill { display: flex; flex-direction: column; min-height: 0; }
.panel.pad { padding: 18px 20px; }
.panel.grow { display: flex; flex-direction: column; min-height: 0; }
.panel-hd {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 12px 16px; border-bottom: 1px solid var(--line);
}
.panel-hd.bare { border: 0; padding: 0 0 12px; }
.panel-hd h3 { margin: 0; font-size: 14px; font-weight: 650; }
.meta { color: var(--muted); font-size: 12px; }

.threat-list { list-style: none; margin: 0; padding: 0; overflow: auto; flex: 1; }
.threat-list li {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 16px; border-bottom: 1px solid var(--line); cursor: pointer;
}
.threat-list li:hover { background: #f7f9fc; }
.tl-body { flex: 1; min-width: 0; }
.tl-body b { display: block; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.tl-body small { color: var(--muted); font-size: 11px; }
.chev { color: var(--muted); font-size: 18px; }

.host-cards { padding: 8px; overflow: auto; flex: 1; }
.host-card {
  width: 100%; display: flex; align-items: center; gap: 10px; text-align: left;
  border: 0; background: transparent; border-radius: 8px; padding: 10px 12px;
}
.host-card:hover { background: #f7f9fc; }
.host-card b { display: block; font-size: 13px; }
.host-card small { color: var(--muted); font-size: 11px; }
.host-card > div { flex: 1; min-width: 0; }

.search {
  border: 1px solid var(--line); border-radius: 8px; padding: 7px 12px;
  min-width: 200px; background: #fff;
}
.field { width: 100%; border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; margin-top: 6px; }
.hint { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
.hint.warn { color: var(--warn); }
.settings label { display: block; font-weight: 600; font-size: 13px; }
.settings .row { display: flex; gap: 8px; margin-top: 14px; }
.rule-stats { margin-top: 20px; padding-top: 16px; border-top: 1px solid var(--line); }
.rule-stats h4 { margin: 0 0 6px; font-size: 13px; }
.rule-stats p { margin: 0 0 8px; color: var(--muted); font-size: 12px; }
.rule-stats ul { margin: 0; padding-left: 1.2em; color: var(--ink-2); font-size: 12px; line-height: 1.7; }

.table-scroll { overflow: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td {
  padding: 11px 14px; text-align: left; border-bottom: 1px solid var(--line);
  white-space: nowrap; max-width: 280px; overflow: hidden; text-overflow: ellipsis; vertical-align: middle;
}
th { background: #fafbfd; color: var(--muted); font-weight: 600; font-size: 12px; position: sticky; top: 0; z-index: 1; }
.strong { font-weight: 650; }
.row-click { cursor: pointer; }
.row-click:hover { background: #f7f9fc; }
.pill {
  display: inline-flex; align-items: center; border-radius: 999px;
  padding: 2px 9px; font-size: 11px; background: #eef1f6; color: var(--muted); font-weight: 600;
}
.pill.on { background: #e8f8ef; color: var(--online); }
.tag {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  background: #f2f4f8; color: var(--ink-2); font-size: 12px;
}
.link { border: 0; background: none; color: var(--accent); font-weight: 600; padding: 0 8px 0 0; }
.link.danger { color: var(--danger); }
.link.muted { color: var(--muted); }
.ops { white-space: nowrap; }
.empty { padding: 40px 20px; text-align: center; color: var(--muted); }
.empty.sm { padding: 28px 16px; }
.empty.err, .err-text { color: var(--danger); }
.toast-stack {
  position: fixed; top: 18px; right: 24px; z-index: 80;
  display: flex; flex-direction: column; gap: 8px; width: min(420px, calc(100vw - 48px));
  pointer-events: none;
}
.toast {
  margin: 0; padding: 12px 14px; border-radius: 10px; font-size: 13px;
  border: 1px solid var(--line); background: #fff; box-shadow: var(--shadow);
  pointer-events: auto; cursor: pointer;
}
.toast.err { background: #fff5f5; border-color: #f3c1c5; color: var(--danger); }
.toast.ok { background: #f0fdf6; border-color: #b7ebc9; color: #027a48; }
.toast.wait { background: #fffaeb; border-color: #fedf89; color: #b54708; }
.toast.float, .toast-with-x {
  display: flex; align-items: flex-start; gap: 10px; cursor: default;
}
.toast-with-x .toast-main { cursor: pointer; }
.toast-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 4px; }
.toast-main b { font-weight: 700; }
.toast-main span { font-size: 12px; line-height: 1.45; word-break: break-word; opacity: .92; }
.toast-x {
  border: 0; background: transparent; color: inherit; opacity: .55;
  font-size: 18px; line-height: 1; padding: 0 2px; cursor: pointer;
}
.toast-x:hover { opacity: 1; }

.dot { width: 8px; height: 8px; border-radius: 50%; background: #c5ccd8; flex-shrink: 0; }
.dot.on { background: var(--online); }

.events-page {
  max-width: none;
  overflow: hidden;
}
.events-page > .page-hd { flex-shrink: 0; margin-bottom: 10px; }
.events-page > .page-hd .desc { display: none; }
.events-page .event-layout,
.events-page .event-layout.single {
  flex: 1; min-height: 0; display: flex; flex-direction: column; overflow: hidden;
}
.events-page .event-main { flex: 1; min-height: 0; display: flex; flex-direction: column; overflow: hidden; gap: 8px; }
.events-page .split {
  flex: 1; min-height: 0; overflow: hidden;
  display: grid; grid-template-columns: 200px minmax(0, 1fr);
  align-items: stretch;
}
.events-page .split.has-detail {
  grid-template-columns: minmax(260px, 1fr) minmax(400px, 46%);
}
.events-page .split > * { min-height: 0; max-height: 100%; overflow: hidden; }
.event-layout { display: grid; grid-template-columns: 120px 1fr; gap: 12px; }
.status-rail {
  background: #fff; border: 1px solid var(--line); border-radius: 12px;
  padding: 6px; height: fit-content; box-shadow: var(--shadow);
}
.status-rail button {
  width: 100%; display: flex; justify-content: space-between; align-items: center;
  border: 0; background: transparent; border-radius: 8px; padding: 10px; color: var(--ink-2); font-size: 13px;
}
.status-rail button.on { background: var(--accent-soft); color: var(--accent); font-weight: 650; }
.event-main { min-width: 0; display: flex; flex-direction: column; gap: 12px; }
.focus-block {
  background: #fff; border: 1px solid var(--line); border-radius: 12px;
  padding: 12px 14px 14px; box-shadow: var(--shadow);
}
.events-page .focus-block {
  flex-shrink: 0;
  padding: 8px 10px 10px;
}
.malware-summary {
  display: flex; flex-wrap: wrap; align-items: flex-end; gap: 16px 24px;
  flex-shrink: 0;
}
.malware-summary .hint { margin: 0; flex: 1 1 200px; }
.mal-stat b { display: block; font-size: 22px; font-weight: 800; color: #b45309; line-height: 1.1; }
.mal-stat span { font-size: 11px; color: var(--muted); font-weight: 650; }
.focus-title { font-size: 13px; font-weight: 650; margin-bottom: 10px; }
.events-page .focus-title { margin-bottom: 6px; font-size: 12px; }
.focus-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(168px, 1fr)); gap: 8px; }
.events-page .focus-grid {
  grid-template-columns: repeat(8, minmax(0, 1fr));
  gap: 6px;
}
.focus-card {
  display: flex; gap: 8px; align-items: center; text-align: left;
  border: 1px solid var(--line); background: #fafbfd; border-radius: 10px; padding: 10px;
}
.events-page .focus-card { padding: 6px 8px; gap: 6px; min-width: 0; }
.events-page .focus-card b { font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.events-page .focus-card em { font-size: 10px; }
.events-page .focus-ico { width: 24px; height: 24px; font-size: 11px; }
.focus-card:hover, .focus-card.on { border-color: #b7c9f0; background: var(--accent-soft); }
.focus-ico {
  width: 30px; height: 30px; border-radius: 8px; color: #fff;
  display: grid; place-items: center; font-size: 12px; font-weight: 700; flex-shrink: 0;
}
.focus-card b { display: block; font-size: 12px; }
.focus-card em { display: block; font-style: normal; color: var(--muted); font-size: 11px; margin-top: 2px; }
.split { display: grid; grid-template-columns: 200px 1fr; gap: 12px; min-height: 400px; }
.events-page .split { gap: 8px; }
.term-pane { background: #fff; border: 1px solid var(--line); border-radius: 12px; overflow: auto; box-shadow: var(--shadow); }
.events-page .term-pane { min-height: 0; overflow: auto; }
.term-hd { padding: 12px; font-size: 13px; }
.term-all, .term-row {
  width: calc(100% - 16px); margin: 0 8px 4px; text-align: left;
  border: 0; background: transparent; border-radius: 8px; padding: 9px;
  display: flex; gap: 8px; align-items: center; color: var(--ink-2); font-size: 13px;
}
.term-all.on, .term-row.on { background: var(--accent-soft); color: var(--accent); font-weight: 650; }
.table-pane { min-width: 0; display: flex; flex-direction: column; }
.sev { font-weight: 700; font-size: 12px; }
.sev[data-s=high], .sev[data-s=critical] { color: var(--danger); }
.sev[data-s=medium] { color: var(--warn); }
.sev[data-s=low], .sev[data-s=info] { color: #2b6de5; }

/* 告警详情 */
.alert-strip {
  display: flex; flex-wrap: wrap; gap: 14px 18px; align-items: center;
  background: #fff; border: 1px solid var(--line); border-radius: 10px;
  padding: 10px 16px; margin-bottom: 12px; font-size: 12px; color: var(--ink-2);
  box-shadow: var(--shadow);
}
.alert-strip b { color: var(--muted); font-weight: 500; margin-right: 4px; }
.sev-box {
  padding: 2px 8px; border-radius: 4px; font-weight: 700; font-size: 12px;
  background: #eff6ff; color: #1d4ed8;
}
.sev-box[data-s=high], .sev-box[data-s=critical] { background: #fef2f2; color: var(--danger); }
.sev-box[data-s=medium] { background: #fffbeb; color: #b45309; }

.detail-toolbar {
  display: flex; justify-content: space-between; align-items: center;
  gap: 12px; margin-bottom: 12px; flex-wrap: wrap;
}
.tabs-line { display: flex; gap: 4px; border-bottom: 1px solid var(--line); }
.tab-line {
  border: 0; background: none; padding: 8px 14px; color: var(--muted);
  font-size: 13px; font-weight: 550; border-bottom: 2px solid transparent; margin-bottom: -1px;
}
.tab-line.on { color: var(--accent); border-bottom-color: var(--accent); }
.toolbar-actions { display: flex; gap: 8px; flex-wrap: wrap; }

.alert-card {
  display: grid; grid-template-columns: 1fr auto; gap: 20px;
  background: #fff; border: 1px solid var(--line); border-radius: 12px;
  padding: 18px 20px; margin-bottom: 14px; box-shadow: var(--shadow);
}
.alert-card h2 { margin: 8px 0 6px; font-size: 18px; font-weight: 700; }
.alert-desc { margin: 0; color: var(--ink-2); font-size: 13px; line-height: 1.6; max-width: 860px; }
.cause { margin-top: 12px; }
.cause label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 4px; }
.cause code {
  display: block; padding: 8px 10px; background: #f7f9fc; border-radius: 6px;
  font-size: 12px; word-break: break-all; color: var(--ink);
}
.meta-row { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 12px; font-size: 12px; color: var(--muted); }
.alert-card-side { display: flex; flex-direction: column; gap: 8px; justify-content: center; }

.evidence-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 10px; margin-bottom: 16px;
}
.ev-item {
  background: #f7f9fc; border-radius: 8px; padding: 10px 12px;
}
.ev-item label { display: block; font-size: 11px; color: var(--muted); margin-bottom: 4px; }
.ev-item div { font-size: 13px; word-break: break-all; font-weight: 500; }
.raw-detail {
  background: #f7f9fc; padding: 12px; border-radius: 8px;
  font-size: 12px; white-space: pre-wrap; overflow: auto; max-height: 200px;
}

.proc-chain {
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
  padding: 16px; background: #fafbfd; border-radius: 10px; border: 1px dashed var(--line);
}
.node {
  display: flex; gap: 10px; align-items: center;
  background: #fff; border: 1px solid var(--line); border-radius: 10px; padding: 10px 14px; min-width: 160px;
}
.node.hot { border-color: #fca5a5; background: #fff7f7; }
.node-ico {
  width: 36px; height: 36px; border-radius: 8px; background: #eef2ff; color: #3730a3;
  display: grid; place-items: center; font-size: 11px; font-weight: 700; flex-shrink: 0;
}
.node b { display: block; font-size: 13px; }
.node small {
  display: block; color: var(--muted); font-size: 11px; max-width: 260px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.arrow { display: flex; flex-direction: column; align-items: center; gap: 4px; color: var(--danger); font-size: 11px; }
.arrow i { width: 64px; height: 2px; background: currentColor; position: relative; }
.arrow i::after {
  content: ''; position: absolute; right: -1px; top: -4px;
  border: 5px solid transparent; border-left-color: currentColor;
}

.snap-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px;
}
.snap-card {
  text-align: left; border: 1px solid var(--line); background: #fff;
  border-radius: 12px; padding: 16px; box-shadow: var(--shadow);
}
.snap-card:hover { border-color: #b7c9f0; }
.snap-top { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.snap-top b { flex: 1; font-size: 14px; }
.snap-card p { margin: 0; color: var(--muted); font-size: 12px; }
.snap-act { margin-top: 10px !important; color: var(--accent) !important; font-weight: 600; }

.host-alerts {
  background: #fff7f7; border: 1px solid #fecaca; border-radius: 10px;
  padding: 8px; margin-bottom: 12px;
}
.ha-hd { font-size: 12px; font-weight: 650; color: #991b1b; padding: 4px 8px 8px; }
.ha-row {
  width: 100%; display: flex; align-items: center; gap: 10px; text-align: left;
  border: 0; background: #fff; border-radius: 8px; padding: 8px 10px; margin-bottom: 4px;
}
.ha-row .strong { flex: 1; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ha-row small { flex-shrink: 0; color: var(--muted); font-size: 11px; }
.host-risk {
  background: #fff; border: 1px solid var(--line); border-radius: 10px;
  padding: 10px 12px; box-shadow: var(--shadow); flex-shrink: 0;
}
.hr-hd {
  display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 8px;
}
.hr-hd b { font-size: 13px; font-weight: 700; }
.hr-hd small { margin-left: 8px; color: var(--muted); font-size: 12px; }
.hr-acts { display: flex; gap: 10px; flex-wrap: wrap; }
.hr-empty { padding: 10px 4px; color: var(--muted); font-size: 12px; line-height: 1.5; }
.hr-list { display: flex; flex-direction: column; gap: 4px; max-height: 220px; overflow: auto; }
.hr-row {
  width: 100%; display: grid; grid-template-columns: auto auto minmax(0, 1fr) auto;
  align-items: center; gap: 8px; text-align: left;
  border: 1px solid #eef2f7; background: #fafbfd; border-radius: 8px; padding: 7px 10px;
}
.hr-row:hover { border-color: #c9d4e3; background: #fff; }
.hr-row b { font-size: 12.5px; font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hr-row small { color: var(--muted); font-size: 11px; white-space: nowrap; }
.hr-kind {
  display: inline-flex; padding: 2px 7px; border-radius: 6px; font-size: 11px; font-weight: 700;
  background: #eef2ff; color: #3730a3; white-space: nowrap;
}
.hr-kind[data-k="threat"] { background: #fee2e2; color: #b91c1c; }

.host-detail {
  overflow: hidden;
  gap: 0;
}
.host-hdr {
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 12px 16px 10px;
  border-bottom: 1px solid var(--line);
  background: #fff;
}
.host-hdr-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}
.host-hdr-id {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  min-width: 0;
}
.host-back { margin-top: 4px; flex-shrink: 0; }
.host-hdr-title { min-width: 0; }
.host-hdr-title h1 {
  margin: 0;
  font-size: 22px;
  font-weight: 750;
  letter-spacing: -0.02em;
  line-height: 1.2;
}
.host-hdr-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 12px;
  margin: 6px 0 0;
  font-size: 12px;
  color: var(--muted);
}
.host-hdr-meta .dot { display: inline-block; }
.host-hdr-acts {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  justify-content: flex-end;
}
.host-more { position: relative; }
.host-more-menu {
  position: absolute;
  right: 0;
  top: calc(100% + 6px);
  z-index: 40;
  min-width: 220px;
  padding: 8px;
  border: 1px solid var(--line);
  border-radius: 10px;
  background: #fff;
  box-shadow: var(--shadow);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.host-more-tags {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 6px 8px 10px;
  border-bottom: 1px solid var(--line);
  margin-bottom: 4px;
  font-size: 11px;
  color: var(--muted);
}
.host-more-tags .field { width: 100%; box-sizing: border-box; }
.host-more-item {
  border: 0;
  background: transparent;
  text-align: left;
  padding: 8px 10px;
  border-radius: 8px;
  font-size: 13px;
  cursor: pointer;
  color: var(--ink);
}
.host-more-item:hover { background: #f4f7fb; }
.host-more-item.danger { color: var(--danger); }
.host-more-item:disabled { opacity: 0.45; cursor: not-allowed; }
.host-hdr-stats {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}
.host-health-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: 1px solid #bfdbfe;
  background: #eff6ff;
  color: #1d4ed8;
  border-radius: 999px;
  padding: 2px 10px;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
}
.host-health-toggle.warn {
  border-color: #fdba74;
  background: #fff7ed;
  color: #c2410c;
}
.host-health-toggle em { font-style: normal; font-weight: 650; opacity: .75; }
.host-health-card {
  border: 1px solid #dbeafe;
  border-radius: 10px;
  background: #f8fbff;
  overflow: hidden;
  max-height: 220px;
  overflow-y: auto;
}
.host-health-body { padding: 10px 12px; }
.snap-shell {
  display: flex; flex-direction: column; gap: 10px;
  flex: 1 1 auto; min-height: 0;
  overflow: hidden;
}
.host-group-nav {
  display: flex; gap: 8px; padding: 10px 14px 0; flex-wrap: wrap;
}
.host-group-btn {
  border: 1px solid var(--line); background: #fff; color: var(--ink-2);
  border-radius: 8px; padding: 7px 14px; font-size: 13px; font-weight: 650; cursor: pointer;
}
.host-group-btn.on {
  background: #0f172a; color: #fff; border-color: #0f172a;
}
.host-group-btn:hover:not(.on) { background: #f4f7fb; }
.host-remote-wrap {
  flex: 1 1 auto; min-height: 0; overflow: auto;
  padding: 18px 20px 24px; box-shadow: var(--shadow);
  background: linear-gradient(180deg, #f8fafc 0%, #fff 120px);
}
.host-remote-hero {
  display: flex; justify-content: space-between; align-items: flex-start; gap: 20px;
  margin-bottom: 18px; padding: 16px 18px; border-radius: 14px;
  border: 1px solid var(--line); background: #fff;
}
.host-remote-hero h2 { margin: 0 0 8px; font-size: 18px; font-weight: 750; letter-spacing: -0.02em; }
.host-remote-hero .hint { margin: 0; max-width: 680px; line-height: 1.55; font-size: 13px; }
.host-remote-steps {
  display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px;
}
.host-remote-steps span {
  font-size: 11px; font-weight: 650; padding: 4px 10px; border-radius: 999px;
  background: #f1f5f9; color: #475569;
}
.host-remote-hero-aside { display: flex; flex-direction: column; align-items: flex-end; gap: 8px; flex-shrink: 0; }
.sync-pill.lg { padding: 8px 14px; font-size: 13px; }
.hr-busy-pill {
  font-size: 11px; font-weight: 650; color: #b45309; background: #fffbeb; border: 1px solid #fde68a;
  padding: 4px 10px; border-radius: 999px;
}
.host-remote-banner {
  display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;
  margin-bottom: 16px; padding-bottom: 14px; border-bottom: 1px dashed var(--line-2);
}
.host-remote-banner b { display: block; font-size: 15px; margin-bottom: 6px; }
.host-remote-banner .hint { margin: 0; max-width: 720px; line-height: 1.5; }
.host-remote-grid {
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px;
}
.host-remote-card {
  background: #fff; border: 1px solid var(--line); border-radius: 12px;
  padding: 14px 16px; min-width: 0;
}
.host-remote-card.wide { grid-column: 1 / -1; }
.host-remote-card h4 { margin: 0 0 10px; font-size: 13px; font-weight: 700; }
.hr-lq-table-wrap { max-height: 420px; overflow: auto; border: 1px solid var(--line); border-radius: 10px; margin-top: 10px; }
.hr-lq-table { font-size: 11px; }
.hr-lq-table td { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.host-sensors-panel { display: none; }
.btn.sm.ghost {
  background: transparent;
  border-color: transparent;
  color: var(--muted);
  padding-left: 6px;
  padding-right: 6px;
}
.btn.sm.ghost:hover { color: var(--ink); background: #f4f7fb; }
.hsp-chip {
  display: inline-flex; align-items: center;
  padding: 2px 8px; border-radius: 999px;
  background: #fff; border: 1px solid #e2e8f0;
  color: #334155; font-size: 11px; line-height: 1.4;
}
.hsp-chip.soft { background: #f8fafc; color: #64748b; }
.hsp-chip.ok { background: #ecfdf5; border-color: #a7f3d0; color: #047857; }
.hsp-chip.warn { background: #fff7ed; border-color: #fdba74; color: #c2410c; }
.hsp-chips, .hsp-channels { margin-top: 6px; }
.hsp-label { font-size: 11px; color: #64748b; font-weight: 600; margin-right: 2px; }
.hsp-drift { margin: 8px 0 0; font-size: 12px; color: #b45309; }
.hsp-row { display: flex; flex-wrap: wrap; gap: 10px 14px; align-items: center; font-size: 12px; }
.hsp-score { font-weight: 700; padding: 2px 8px; border-radius: 6px; background: #ecfdf5; color: #047857; }
.hsp-score[data-lv="fair"] { background: #fffbeb; color: #b45309; }
.hsp-score[data-lv="poor"] { background: #fef2f2; color: #b91c1c; }
.hsp-advise { margin: 8px 0 0; padding-left: 18px; color: #92400e; font-size: 12px; line-height: 1.45; }
.host-remote-links, .host-remote-btns { display: flex; flex-wrap: wrap; gap: 8px; }
.hr-field { display: flex; flex-direction: column; gap: 4px; margin-bottom: 10px; }
.hr-field span { font-size: 11px; color: var(--muted); font-weight: 650; }
.hr-field .field { width: 100%; box-sizing: border-box; }
.host-remote-cmd-hd { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 10px; }
.host-remote-cmd-hd h4 { margin: 0; }
.host-remote-cmd-table { width: 100%; font-size: 12px; }
.host-remote-cmd-table th, .host-remote-cmd-table td { padding: 8px 10px; text-align: left; vertical-align: top; }
.btn.block { display: block; width: 100%; margin-bottom: 10px; }
.host-remote-subnav {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 10px; margin-bottom: 18px;
}
.hr-tab {
  display: flex; flex-direction: column; align-items: flex-start; gap: 2px;
  text-align: left; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--line);
  background: #fff; cursor: pointer; transition: border-color 0.15s, box-shadow 0.15s;
}
.hr-tab:hover { border-color: #cbd5e1; background: #f8fafc; }
.hr-tab.on {
  border-color: #c81626; background: #fff5f5; box-shadow: 0 0 0 1px rgba(200, 22, 38, 0.12);
}
.hr-tab-label { font-size: 13px; font-weight: 700; color: var(--ink); }
.hr-tab-hint { font-size: 10px; color: var(--muted); line-height: 1.3; }
.host-remote-panel { margin-bottom: 16px; }
.hr-shell-panel { max-width: none; }
.hr-shell-layout {
  display: grid; grid-template-columns: minmax(0, 1fr) 200px; gap: 14px; align-items: start;
}
.hr-shell-aside {
  background: #fff; border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px;
}
.hr-shell-aside h4 { margin: 0 0 6px; font-size: 13px; }
.hr-shell-quick { margin-bottom: 6px; text-align: left; font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
.hr-fs-explorer {
  display: grid; grid-template-columns: 240px minmax(0, 1fr); gap: 12px; min-height: 320px;
}
.hr-fs-tree, .hr-fs-main {
  border: 1px solid var(--line); border-radius: 12px; background: #fff; min-height: 280px;
}
.hr-fs-tree { overflow: auto; max-height: 520px; padding-bottom: 8px; }
.hr-fs-tree-hd, .hr-fs-crumb {
  margin: 0; padding: 10px 12px; font-size: 12px; font-weight: 700; color: var(--ink-2);
  border-bottom: 1px solid var(--line); position: sticky; top: 0; background: #fff;
}
.hr-fs-crumb { font-weight: 550; }
.hr-fs-tree-ul { list-style: none; margin: 6px 0 0; padding: 0; }
.hr-fs-node {
  width: 100%; display: flex; align-items: center; gap: 6px; text-align: left;
  border: 0; background: transparent; padding: 5px 8px; cursor: pointer; font-size: 12px;
}
.hr-fs-node:hover { background: #f4f7fb; }
.hr-fs-node.on { background: #fff5f5; color: #9f1239; }
.hr-fs-caret { width: 12px; font-size: 9px; color: var(--muted); flex-shrink: 0; }
.hr-fs-node-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hr-fs-node em { font-style: normal; font-size: 10px; color: var(--muted); flex-shrink: 0; }
.hr-fs-main { padding: 0 0 10px; overflow: auto; max-height: 520px; }
.hr-fs-drives {
  display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 12px;
}
.hr-fs-drives-label { font-size: 11px; font-weight: 700; color: var(--muted); margin-right: 4px; }
.hr-fs-drive {
  display: flex; flex-direction: column; align-items: flex-start; gap: 2px;
  min-width: 56px; padding: 8px 12px; border-radius: 10px; border: 1px solid var(--line);
  background: #fff; cursor: pointer; font-size: 12px;
}
.hr-fs-drive.on { border-color: #c81626; background: #fff5f5; }
.hr-fs-drive strong { font-size: 15px; }
.hr-fs-drive em { font-style: normal; font-size: 10px; color: var(--muted); }
.hr-fs-row { cursor: pointer; }
.hr-fs-icon { margin-right: 6px; opacity: 0.85; }
.hr-fs-preview-ph { align-self: center; }
.hr-reg-shortcuts { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
.hr-reg-chip {
  border: 1px solid var(--line); background: #f8fafc; border-radius: 999px;
  padding: 4px 12px; font-size: 11px; font-weight: 650; cursor: pointer;
}
.hr-reg-chip:hover { background: #eef2f7; }
.hr-reg-crumb { margin: 0 0 12px; font-size: 12px; color: var(--ink-2); word-break: break-all; }
.hr-reg-body { display: flex; flex-direction: column; gap: 16px; }
.hr-reg-section h4 { margin: 0 0 8px; font-size: 13px; }
.hr-reg-subkey-list { display: flex; flex-wrap: wrap; gap: 6px; }
.hr-reg-subkey {
  border: 1px dashed #cbd5e1; background: #fff; border-radius: 8px; padding: 6px 10px;
  font-size: 12px; font-family: ui-monospace, Consolas, monospace; cursor: pointer;
}
.hr-reg-subkey:hover { border-color: #c81626; background: #fff5f5; }
.hr-reg-dl { display: grid; gap: 8px; margin: 0; font-size: 12px; }
.hr-reg-dl dt { font-weight: 650; color: var(--muted); font-size: 11px; }
.hr-reg-data { word-break: break-all; max-width: 100%; }
.hr-reg-val-table .hr-reg-data { max-width: 480px; }
.hr-shell-card {
  border: 1px solid #1e293b; border-radius: 14px; overflow: hidden;
  box-shadow: 0 12px 40px rgba(15, 23, 42, 0.12);
}
.hr-shell-hd {
  display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 10px;
  padding: 10px 14px; background: #1e293b; color: #e2e8f0; font-size: 12px;
}
.hr-shell-status { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.hr-shell-led {
  width: 8px; height: 8px; border-radius: 50%; background: #64748b; flex-shrink: 0;
}
.hr-shell-led.live { background: #22c55e; box-shadow: 0 0 8px #22c55e; }
.hr-shell-led.connecting { background: #fbbf24; animation: hr-pulse 1s infinite; }
.hr-shell-led.error { background: #ef4444; }
.hr-shell-led.idle { background: #64748b; }
@keyframes hr-pulse { 50% { opacity: 0.45; } }
.hr-shell-sid { font-size: 10px; opacity: 0.75; padding: 2px 6px; background: rgba(0,0,0,0.25); border-radius: 4px; }
.hr-shell-actions { display: flex; gap: 8px; }
.hr-shell-body {
  min-height: 280px; max-height: 420px; overflow: auto; padding: 14px 16px;
  background: #0b1120; font-family: ui-monospace, Consolas, monospace; font-size: 12px; line-height: 1.5;
}
.hr-shell-empty { color: #94a3b8; text-align: center; padding: 48px 16px; }
.hr-shell-empty p { margin: 0 0 8px; }
.hr-shell-line { white-space: pre-wrap; word-break: break-word; margin-bottom: 4px; }
.hr-shell-line.sys { color: #94a3b8; font-style: italic; }
.hr-shell-line.in { color: #fde68a; }
.hr-shell-line.in::before { content: '> '; color: #64748b; }
.hr-shell-line.out { color: #86efac; }
.hr-shell-line.err { color: #fca5a5; }
.hr-shell-inputbar {
  display: flex; align-items: center; gap: 8px; padding: 10px 12px;
  background: #1e293b; border-top: 1px solid #334155;
}
.hr-shell-prompt { color: #86efac; font-family: ui-monospace, Consolas, monospace; font-weight: 700; }
.hr-shell-input { background: #0f172a !important; color: #e2e8f0 !important; border-color: #334155 !important; }
.hr-shell-foot { margin-top: 10px; }
.hr-shell-banner {
  margin: 0; padding: 8px 14px; font-size: 12px; border-bottom: 1px solid #334155;
}
.hr-shell-banner.ok { background: #14532d; color: #bbf7d0; }
.hr-shell-banner.err { background: #7f1d1d; color: #fecaca; }
.hr-shell-banner.warn { background: #78350f; color: #fde68a; }
.hr-shell-banner.info { background: #1e3a5f; color: #bae6fd; }
.host-remote-toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
.host-remote-toolbar .grow { flex: 1; min-width: 200px; }
.host-remote-split { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; min-height: 120px; }
.host-remote-pre {
  margin: 0; padding: 12px; background: #0f172a; color: #e2e8f0; border-radius: 10px;
  font-size: 12px; line-height: 1.45; max-height: 360px; overflow: auto; white-space: pre-wrap; word-break: break-all;
}
.host-remote-cmd-in { width: 100%; box-sizing: border-box; margin-bottom: 8px; }
.host-remote-cmd-log { margin-top: 12px; font-size: 12px; }
.host-remote-log-line { padding: 4px 0; border-bottom: 1px dashed var(--line-2); }
.host-remote-log-line em { color: var(--muted); font-style: normal; margin-right: 8px; }
@media (max-width: 960px) {
  .host-remote-grid { grid-template-columns: 1fr; }
  .host-remote-split { grid-template-columns: 1fr; }
  .hr-fs-explorer { grid-template-columns: 1fr; }
  .hr-shell-layout { grid-template-columns: 1fr; }
}
.settings-rules-table {
  overflow: auto;
}
.settings-rules-table table { width: 100%; }
.settings-rules-table thead th {
  position: sticky; top: 0; background: #fafbfd; z-index: 1;
}
.settings-extra { display: none; }
.ov-empty { padding: 28px 16px; text-align: center; }
.ov-empty .hint { margin: 6px 0 12px; }
.mod-tabs.bar {
  display: flex; gap: 0; flex-wrap: wrap;
  background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 4px;
  box-shadow: var(--shadow); width: 100%; flex-shrink: 0;
}
.mod-tab {
  border: 0; background: transparent; border-radius: 6px;
  padding: 8px 14px; font-size: 13px; font-weight: 550; color: var(--ink-2);
}
.mod-tab.on { background: #c81626; color: #fff; }
.snap-flags {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center; flex-shrink: 0;
}
.sflag {
  display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 999px;
  font-size: 12px; font-weight: 650; background: #f1f5f9; color: #475569;
}
.sflag[data-t="bad"] { background: #fef2f2; color: #b91c1c; }
.sflag[data-t="warn"] { background: #fff7ed; color: #c2410c; }
.sflag[data-t="info"] { background: #eff6ff; color: #1d4ed8; }
.sflag.muted { background: transparent; color: var(--muted); font-weight: 500; padding-left: 2px; }
.snap-work {
  display: grid; grid-template-columns: minmax(0, 1.4fr) minmax(300px, .9fr); gap: 12px;
  flex: 1 1 auto; min-height: 0; align-items: stretch;
  overflow: hidden;
}
.snap-work.has-detail { grid-template-columns: minmax(0, 1.4fr) minmax(300px, .9fr); }
.snap-sum { display: flex; flex-direction: column; min-height: 0; overflow: auto; }
.ss-kpis {
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; padding: 12px 14px;
}
.ss-kpis > div {
  background: #f5f8fc; border: 1px solid #e8eef6; border-radius: 8px; padding: 10px 12px;
}
.ss-kpis span { display: block; font-size: 11px; color: var(--muted); margin-bottom: 4px; }
.ss-kpis strong { font-size: 22px; font-weight: 720; letter-spacing: -.03em; }
.ss-kpis .c-warn { color: #c2410c; }
.ss-kpis .c-danger { color: #b91c1c; }
.ss-list { padding: 0 12px 10px; display: flex; flex-direction: column; gap: 6px; }
.ss-list h4 { margin: 4px 0 6px; font-size: 12px; color: var(--muted); }
.ss-row {
  display: grid; grid-template-columns: auto 1fr; gap: 2px 10px; text-align: left;
  border: 1px solid var(--line); background: #fff; border-radius: 8px; padding: 8px 10px;
}
.ss-row b { font-size: 13px; grid-column: 2; }
.ss-row small { grid-column: 2; color: var(--muted); font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ss-row .sev { grid-row: 1 / span 2; align-self: center; }
.ss-acts { display: flex; gap: 8px; padding: 10px 14px 14px; border-top: 1px solid var(--line); margin-top: auto; }
.sd-groups { overflow: auto; flex: 1; }
.sd-group { padding: 4px 0 8px; border-bottom: 1px solid var(--line-2); }
.sd-group h4 {
  margin: 0; padding: 10px 16px 6px; font-size: 12px; color: var(--muted); font-weight: 700;
}
.sd-dl.compact-gap { padding-top: 0; }
.hunt-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px;
}
.hunt-card {
  text-align: left; border: 1px solid var(--line); background: #fff; border-radius: 12px;
  padding: 18px 16px; box-shadow: var(--shadow);
}
.hunt-card b { display: block; font-size: 15px; margin-bottom: 6px; }
.hunt-card span { color: var(--accent); font-size: 12px; font-weight: 600; }
.events-page .table-pane {
  min-height: 0; height: 100%;
  display: flex; flex-direction: column; min-width: 0;
  overflow: hidden;
}
.events-page .table-pane .panel-hd { flex-shrink: 0; }
.events-page .table-pane .table-scroll { flex: 1 1 auto; min-height: 0; overflow: auto; }
.events-page .table-pane .list-pager {
  flex: 0 0 auto; flex-shrink: 0;
  position: relative; z-index: 3;
  border-top: 1px solid #dbe3f0;
  box-shadow: 0 -4px 12px rgba(15, 23, 42, .04);
}
.events-page .row-click.on td,
.behaviors-page .row-click.on td,
.attck-page .row-click.on td { background: #eef4ff; }
.btn.sm.primary { background: var(--accent); border-color: var(--accent); color: #fff; }

.ed-side {
  display: flex; flex-direction: column; min-width: 0; min-height: 0; overflow: hidden;
  border: 1px solid var(--line); border-radius: 12px; background: #f5f7fa; box-shadow: var(--shadow);
}
.ed-top {
  flex-shrink: 0; background: #fff; border-bottom: 1px solid #e8eef6; padding: 12px 14px 14px;
}
.ed-top-l {
  display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 12px;
}
.ed-top-l > b { font-size: 13px; font-weight: 700; color: var(--ink); }
.ed-nav { display: flex; align-items: center; gap: 10px; }
.ed-nav .btn-text:disabled { opacity: .35; cursor: not-allowed; }
.ed-x {
  width: 28px; height: 28px; border: 0; border-radius: 8px; background: #f1f5f9;
  font-size: 18px; line-height: 1; color: #667085; cursor: pointer;
}
.ed-x:hover { background: #e2e8f0; }
.ed-hero { display: flex; align-items: flex-start; gap: 12px; }
.ed-shield {
  width: 40px; height: 40px; border-radius: 50%; flex-shrink: 0;
  background: linear-gradient(145deg, #ef4444, #b91c1c); color: #fff;
  display: grid; place-items: center; font-weight: 800; font-size: 18px;
  box-shadow: 0 6px 14px rgba(185, 28, 28, .28);
}
.ed-hero-main { flex: 1; min-width: 0; display: flex; flex-direction: column; align-items: flex-start; gap: 8px; }
.ed-hero-main h2 {
  margin: 0; font-size: 15px; font-weight: 700; line-height: 1.4;
  word-break: break-word; max-width: 100%;
}
.ed-hero-meta { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; font-size: 12px; }
.ed-st[data-s="open"] { color: #c2410c; font-weight: 650; }
.ed-st[data-s="closed"] { color: #059669; font-weight: 650; }
.ed-st[data-s="ignored"] { color: #64748b; font-weight: 650; }
.ed-open { flex-shrink: 0; white-space: nowrap; }
.ed-scroll {
  flex: 1 1 auto; min-height: 0; overflow-x: hidden; overflow-y: auto;
  padding: 10px 12px 24px;
  display: flex; flex-direction: column; gap: 10px;
  -webkit-overflow-scrolling: touch;
}
.ed-card {
  background: #fff; border: 1px solid #e6ebf2; border-radius: 10px; overflow: hidden;
  flex-shrink: 0;
}
.ed-card-hd {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 10px 12px; cursor: pointer; user-select: none;
}
.ed-card-hd b {
  font-size: 13px; font-weight: 700; color: var(--ink);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0;
}
.ed-card-hd i {
  font-style: normal; width: 22px; height: 22px; border-radius: 6px; border: 1px solid #e2e8f0;
  display: grid; place-items: center; font-size: 14px; color: #64748b; background: #f8fafc; flex-shrink: 0;
}
.ed-card-bd { padding: 0 12px 12px; }
.ed-dl { margin: 0; display: flex; flex-direction: column; gap: 0; }
.ed-dl > div {
  display: grid; grid-template-columns: 88px minmax(0, 1fr); gap: 6px 10px;
  padding: 6px 0; border-bottom: 1px solid #f1f5f9; font-size: 12.5px;
  align-items: start;
}
.ed-dl > div:last-child { border-bottom: 0; }
.ed-dl dt { color: #98a2b3; margin: 0; font-weight: 600; line-height: 1.45; }
.ed-dl dd {
  margin: 0; color: var(--ink); word-break: break-word; overflow-wrap: anywhere;
  line-height: 1.45; min-width: 0;
}
.ed-root { font-weight: 650; }
.ed-more {
  margin-top: 6px; border: 0; background: none; color: var(--accent);
  font-size: 12px; font-weight: 600; cursor: pointer; padding: 0;
}
.ed-host-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 8px;
}
.ed-host-cell {
  background: #f7f9fc; border: 1px solid #e8eef6; border-radius: 8px; padding: 10px 12px;
  min-width: 0;
}
.ed-k { display: block; font-size: 11px; color: #98a2b3; font-weight: 650; margin-bottom: 6px; }
.ed-host-name {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
}
.ed-host-name b {
  font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%;
}
.ed-host-name em { font-style: normal; font-size: 11px; font-weight: 650; }
.ed-host-name em.on { color: #059669; }
.ed-host-name em.off { color: #94a3b8; }
.ed-host-sub {
  display: flex; flex-wrap: wrap; gap: 6px 10px; margin-top: 8px;
  font-size: 11px; color: #667085; font-variant-numeric: tabular-nums;
}
.ed-user b { display: block; font-size: 13px; color: #0f172a; word-break: break-all; }
.ed-user small { display: block; margin-top: 4px; font-size: 11px; color: #667085; word-break: break-all; }
.ed-kv {
  display: grid; grid-template-columns: 1fr 1fr; gap: 6px 10px;
}
.ed-kv > div {
  min-width: 0; background: #f8fafc; border: 1px solid #eef2f7; border-radius: 8px;
  padding: 8px 10px;
}
.ed-kv > div.span2 { grid-column: 1 / -1; }
.ed-kv span {
  display: block; font-size: 11px; color: #98a2b3; font-weight: 650; margin-bottom: 4px;
}
.ed-kv b {
  display: block; font-size: 12.5px; font-weight: 650; color: var(--ink);
  word-break: break-word; overflow-wrap: anywhere; line-height: 1.4;
}
.ed-attck-sum { margin: 0 0 10px; font-size: 13px; color: var(--ink-2); line-height: 1.5; }
.ed-attck-sum b { color: #b91c1c; }
.ed-attck-sum code {
  font-size: 12px; font-weight: 700; color: #b91c1c; background: #fff1f2; padding: 1px 6px; border-radius: 5px;
}
.ed-attck-grid {
  display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 6px;
}
.ed-attck-cell {
  border: 1px solid #e8eef6; background: #fafbfd; border-radius: 8px; padding: 8px;
  display: flex; flex-direction: column; gap: 2px; min-width: 0;
}
.ed-attck-cell em { font-style: normal; font-size: 10px; color: #98a2b3; font-weight: 700; }
.ed-attck-cell b {
  font-size: 12px; font-weight: 650; color: #667085;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ed-attck-cell span { font-size: 11px; color: #c0c8d4; }
.ed-attck-cell.hit {
  border-color: rgba(225,29,46,.35); background: #fff5f5;
}
.ed-attck-cell.hit b { color: #7a2a30; }
.ed-attck-cell.hit span { color: #b91c1c; font-weight: 700; }
.ed-dl-extra { margin-top: 8px; border-top: 1px dashed #e2e8f0; padding-top: 4px; }
.ed-tabs {
  display: flex; gap: 2px; border-bottom: 1px solid #e8eef6; margin-bottom: 10px;
}
.ed-tabs button {
  border: 0; background: none; padding: 8px 12px; font-size: 13px; font-weight: 650;
  color: #667085; border-bottom: 2px solid transparent; margin-bottom: -1px; cursor: pointer;
}
.ed-tabs button.on { color: #b91c1c; border-bottom-color: #e11d2e; }
.ed-beh {
  display: flex; flex-direction: column; gap: 6px;
  max-height: 200px; overflow: auto; min-height: 0;
}
.ed-beh-row {
  display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 8px; align-items: start;
  padding: 8px 10px; background: #f8fafc; border-radius: 8px;
}
.ed-beh-main { min-width: 0; }
.ed-beh-main b {
  display: block; font-size: 12.5px; font-weight: 650;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ed-beh-main small {
  display: block; font-size: 11px; color: var(--muted); margin-top: 2px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ed-beh-main em {
  display: block; font-style: normal; font-size: 11px; color: #98a2b3; margin-top: 4px;
}
.ed-file-ico {
  width: 22px; height: 22px; border-radius: 6px; background: #fee2e2; color: #b91c1c;
  display: grid; place-items: center; font-size: 11px; font-weight: 700;
}
.ed-acts { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }

.behaviors-page { overflow: hidden; display: flex; flex-direction: column; min-height: 0; gap: 10px; }
.bh-top {
  display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-shrink: 0;
  background: #fff; border: 1px solid rgba(15,23,42,.06); border-radius: 12px; padding: 12px 16px;
}
.bh-top h1 { margin: 0; font-size: 20px; font-weight: 700; }
.bh-top-r { display: flex; align-items: center; gap: 10px; }
.bh-filters {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center; flex-shrink: 0; padding: 10px 12px;
}
.bh-filters .grow { flex: 1 1 180px; min-width: 140px; }
.bh-stats {
  display: grid; grid-template-columns: minmax(220px, .85fr) minmax(0, 1.4fr) minmax(240px, 1fr);
  gap: 10px; flex-shrink: 0;
}
.bh-stats > .panel { min-height: 0; display: flex; flex-direction: column; overflow: hidden; }
.bh-stats > .panel.bh-stage { overflow: visible; }
.bh-sev-body { padding: 8px 14px 14px; display: flex; flex-direction: column; gap: 14px; }
.bh-sev-row { display: flex; gap: 10px; align-items: flex-start; }
.bh-ico {
  width: 32px; height: 32px; border-radius: 50%; display: grid; place-items: center;
  font-size: 12px; font-weight: 700; color: #fff; flex-shrink: 0;
}
.bh-ico.threat { background: #e11d2e; }
.bh-ico.risk { background: #f79009; }
.bh-sev-main { flex: 1; min-width: 0; }
.bh-sev-main b { display: block; font-size: 13px; margin-bottom: 6px; }
.bh-sev-main em { font-style: normal; color: #b91c1c; margin-left: 6px; }
.bh-sev-main small { color: var(--muted); font-size: 11px; }
.bh-bar {
  height: 8px; border-radius: 4px; background: #eef1f6; overflow: hidden; margin-bottom: 4px;
}
.bh-bar > i, .bh-bar i { display: block; height: 100%; border-radius: 4px; background: #98a2b3; }
.bh-bar > i.threat, .bh-bar i.threat { background: #e11d2e; }
.bh-bar > i.risk, .bh-bar i.risk { background: #f79009; }
.bh-wave {
  position: relative; height: 148px; margin: 4px 18px 8px; overflow: visible;
}
.bh-wave-svg {
  position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible;
}
.bh-wave-path { filter: drop-shadow(0 2px 4px rgba(225, 29, 46, .12)); }
.bh-wave-node {
  position: absolute; z-index: 2; width: 36px; height: 36px; border-radius: 50%;
  transform: translate(-50%, -50%); border: 3px solid #fff;
  background: linear-gradient(145deg, #cbd5e1, #94a3b8); color: #fff;
  display: grid; place-items: center;
  cursor: pointer; box-shadow: 0 4px 12px rgba(185, 28, 28, .22);
  padding: 0;
}
.bh-wave-node .bh-ico-svg {
  width: 16px; height: 16px; display: block; pointer-events: none;
}
.bh-wave-node.dim {
  background: linear-gradient(145deg, #dbe3ee, #94a3b8) !important;
  box-shadow: 0 2px 6px rgba(100, 116, 139, .2);
  opacity: .85;
}
.bh-wave-node.hit:not(.dim) {
  box-shadow: 0 4px 12px rgba(185, 28, 28, .28);
}
.bh-wave-node.on {
  outline: 3px solid rgba(225, 29, 46, .35); outline-offset: 2px;
}
.bh-wave-legend {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 6px 12px;
  padding: 4px 14px 14px;
}
.bh-leg {
  display: flex; align-items: center; gap: 6px; min-width: 0;
  border: 0; background: transparent; padding: 4px 2px; cursor: pointer; text-align: left;
  border-radius: 6px;
}
.bh-leg:hover { background: #f8fafc; }
.bh-leg.on { background: #fff1f2; }
.bh-leg i {
  width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
}
.bh-leg span {
  flex: 1; min-width: 0; font-size: 12px; color: #475569; font-weight: 550;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.bh-leg b {
  font-size: 13px; font-weight: 700; color: #98a2b3; font-variant-numeric: tabular-nums;
}
.bh-leg.hit b { color: #b91c1c; }
.bh-leg.hit span { color: #7a2a30; }
.bh-top-list { padding: 4px 12px 12px; overflow: auto; flex: 1; min-height: 0; }
.bh-top-row {
  display: grid; grid-template-columns: 22px 1fr auto; gap: 8px; align-items: center;
  width: 100%; border: 0; background: transparent; padding: 7px 4px; border-radius: 8px;
  text-align: left; cursor: pointer;
}
.bh-top-row:hover { background: #f8fafc; }
.bh-top-row > em {
  font-style: normal; width: 20px; height: 20px; border-radius: 6px; background: #f2f4f7;
  display: grid; place-items: center; font-size: 11px; font-weight: 700; color: #667085;
}
.bh-top-row:nth-child(-n+3) > em { background: #fff1f0; color: #c2410c; }
.bh-top-main { min-width: 0; }
.bh-top-main b {
  display: block; font-size: 12px; font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.bh-top-main .bh-bar { margin: 4px 0 0; }
.bh-top-row strong { font-size: 13px; font-weight: 700; }
.bh-bottom {
  flex: 1; min-height: 0; display: grid; grid-template-columns: 220px minmax(0, 1fr); gap: 10px;
}
.bh-hosts, .bh-list { min-height: 0; display: flex; flex-direction: column; overflow: hidden; }
.bh-host-scroll { flex: 1; min-height: 0; overflow: auto; padding-bottom: 8px; }
.bh-list .table-scroll { flex: 1; min-height: 0; overflow: auto; }
.bh-list .list-pager { flex-shrink: 0; }
.evt-expand-row > td { padding: 0 !important; background: #f7f9fc; }
.evt-inline {
  padding: 12px 14px; background: linear-gradient(180deg, #f4f7fb 0%, #fafbfd 100%);
  border-top: 1px solid #e2e8f0;
}
.evt-inline .ep-hd { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }
.evt-inline .ep-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.evt-inline .ep-title b { font-size: 13px; }
.evt-inline .ep-acts { display: flex; gap: 6px; flex-wrap: wrap; }
.evt-inline .ep-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.evt-inline .ep-col h4 { margin: 0 0 8px; font-size: 12px; color: var(--muted); }
@media (max-width: 1200px) {
  .bh-stats { grid-template-columns: 1fr; max-height: none; }
  .bh-bottom { grid-template-columns: 1fr; }
  .ed-host-grid { grid-template-columns: 1fr; }
}
@media (max-width: 1100px) {
  .events-page .split.has-detail { grid-template-columns: 1fr; }
  .ed-side { max-height: min(56vh, 520px); }
}
.snap-list { display: flex; flex-direction: column; min-height: 0; min-width: 0; height: 100%; }
.snap-list .panel-hd { flex-wrap: wrap; flex-shrink: 0; }
.snap-table { flex: 1 1 0; min-height: 0; max-height: none; overflow: auto; }
.snap-table tr.active { background: #eef4ff; }
.snap-detail {
  display: flex; flex-direction: column; min-height: 0; height: 100%; overflow: hidden;
}
.sd-hd {
  display: flex; justify-content: space-between; align-items: flex-start; gap: 10px;
  padding: 14px 16px; border-bottom: 1px solid var(--line);
}
.sd-hd b { display: block; font-size: 14px; word-break: break-word; }
.sd-hd small { color: var(--muted); font-size: 11px; }
.icon-x {
  width: 28px; height: 28px; border: 0; background: #f3f5f9; border-radius: 8px;
  font-size: 18px; color: var(--muted); line-height: 1; flex-shrink: 0;
}
.sd-dl {
  margin: 0; padding: 12px 16px; overflow: auto; flex: 1;
  display: flex; flex-direction: column; gap: 10px;
}
.sd-dl > div {
  display: grid; grid-template-columns: 100px 1fr; gap: 10px;
  padding-bottom: 8px; border-bottom: 1px solid var(--line-2); font-size: 12px;
}
.sd-dl dt { color: var(--muted); margin: 0; }
.sd-dl dd { margin: 0; word-break: break-all; font-weight: 500; color: var(--ink); white-space: pre-wrap; }
.sd-actions { padding: 10px 12px 14px; border-top: 1px solid var(--line); }
.sd-actions h4 { margin: 0 0 8px; font-size: 12px; }

.sysinfo-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 10px; padding: 16px;
}
.si-item { background: #f7f9fc; border-radius: 8px; padding: 12px; }
.si-item label { display: block; font-size: 11px; color: var(--muted); margin-bottom: 4px; }
.si-item div { font-size: 13px; font-weight: 550; word-break: break-all; }

.deploy-grid { display: grid; grid-template-columns: 1.1fr .9fr; gap: 14px; }
.rel-box { margin-top: 12px; padding: 10px 12px; border: 1px solid var(--line, #e3e6ea); border-radius: 8px; background: var(--bg-2, #f7f8fa); }
.rel-box.rel-stale, .rel-box.rel-unverified, .rel-box.rel-mismatch, .rel-box.rel-missing { border-color: #e0a030; }
.rel-hd { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.rel-line { margin-top: 6px; font-size: 12px; color: var(--ink-2); }
.rel-warn { margin-top: 6px; font-size: 12px; color: #b26a00; }
.health-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.hchip { font-size: 12px; padding: 1px 8px; border-radius: 10px; background: #eef2f7; color: #4a5568; }
.hchip.warn { background: #fff3e0; color: #b26a00; }
.ent-link { cursor: pointer; color: #2563eb; }
.ent-link:hover { text-decoration: underline; }
.ent-ev { display: flex; gap: 8px; align-items: baseline; font-size: 12px; padding: 3px 0; border-bottom: 1px dashed #eef0f3; }
.ent-ev > span:last-child { flex: 1; min-width: 0; word-break: break-all; }
tr.row-warn td { background: #fff8ec; }
.rel-act { margin-top: 10px; display: flex; align-items: center; gap: 10px; }
.deploy-grid ol { margin: 8px 0 0; padding-left: 1.2em; color: var(--ink-2); line-height: 1.8; }
.deploy-grid p { color: var(--muted); margin: 8px 0 0; }

.btn.sm { padding: 5px 10px; font-size: 12px; }
.btn.sm.outline.danger {
  color: var(--danger);
  border-color: #e8b4b8;
  background: #fff;
}
.rules-toolbar {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 0 14px 12px;
}
.rules-filter-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px;
}
.rules-toolbar-label {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.04em;
  color: #64748b;
  text-transform: uppercase;
}
.rules-filter-chips { padding: 0; gap: 6px; }
.rules-bulk-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: stretch;
}
.rules-bulk-card {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 10px 12px;
  padding: 8px 12px;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  background: #f8fafc;
  min-height: 42px;
}
.rules-bulk-card.elastic {
  background: #f8fbff;
  border-color: #dbeafe;
}
.rules-bulk-card-hd {
  font-size: 12px;
  font-weight: 700;
  color: #334155;
  white-space: nowrap;
}
.rules-bulk-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 14px;
}
.rules-bulk-pair {
  display: inline-flex;
  align-items: center;
  gap: 0;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  overflow: hidden;
  background: #fff;
}
.rules-bulk-pair em {
  font-style: normal;
  font-size: 11px;
  font-weight: 650;
  color: #64748b;
  padding: 0 8px;
  border-right: 1px solid #eef2f7;
  white-space: nowrap;
}
.rbb {
  border: 0;
  background: transparent;
  padding: 5px 11px;
  font-size: 12px;
  font-weight: 650;
  cursor: pointer;
  color: #334155;
  line-height: 1.2;
}
.rbb + .rbb { border-left: 1px solid #eef2f7; }
.rbb.on:hover:not(:disabled) { background: #ecfdf5; color: #047857; }
.rbb.off { color: #b42318; }
.rbb.off:hover:not(:disabled) { background: #fef2f2; }
.rbb:disabled { opacity: 0.45; cursor: not-allowed; }
.rules-bulk-hint { margin: 0; }
.chip {
  display: inline-flex; align-items: center; border: 1px solid var(--line);
  background: #fff; border-radius: 999px; padding: 5px 12px; color: var(--muted); font-size: 12px;
}
.mono { font-variant-numeric: tabular-nums; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.muted { color: var(--muted); }
.tools { display: flex; gap: 8px; }

.op-group { display: inline-flex; gap: 6px; align-items: center; }
.op-ico {
  width: 30px; height: 30px; border-radius: 8px; border: 1px solid var(--line);
  background: #fff; color: var(--ink-2); display: inline-grid; place-items: center;
  font-size: 12px; font-weight: 650; transition: .15s;
}
.op-ico:hover { border-color: #c5d0e0; background: #f7f9fc; color: var(--ink); }
.op-ico.primary {
  border-color: #fecaca; background: #fff5f5; color: #dc2626;
}
.op-ico.primary:hover { background: #fee2e2; border-color: #fca5a5; }
.events-page .table-pane {
  border: 1px solid var(--line); border-radius: 12px;
  box-shadow: var(--shadow);
}
.events-page .term-pane {
  border-radius: 12px;
}
.events-page .focus-block {
  background: linear-gradient(180deg, #fff 0%, #fafbfd 100%);
}
.events-page .row-click:hover td { background: #f5f8ff; }
.events-page .tag {
  background: #eef2ff; color: #3730a3; border-radius: 6px; font-weight: 600;
}
.event-layout.single { display: block; }
.events-page .event-layout.single { display: flex; flex-direction: column; }
.event-layout.single .event-main { display: flex; flex-direction: column; gap: 12px; min-height: 0; }

.td-dl { margin: 0; display: flex; flex-direction: column; gap: 8px; }
.td-dl > div { display: grid; grid-template-columns: 88px 1fr; gap: 8px; font-size: 12px; }
.td-dl dt { color: var(--muted); margin: 0; }
.td-dl dd { margin: 0; word-break: break-all; color: var(--ink); font-weight: 500; }
.td-dl.compact > div { grid-template-columns: 72px 1fr; }
.intel { background: #f8fafc; border-radius: 8px; padding: 10px 12px; }
.intel-tip { margin: 0 0 8px; font-size: 12px; color: #1d4ed8; }
.virus-tag {
  display: inline-block; margin-bottom: 10px; padding: 4px 8px; border-radius: 4px;
  border: 1px solid #fecaca; background: #fff; color: #b91c1c; font-size: 12px; font-weight: 600;
  max-width: 100%; word-break: break-word;
}

/* 威胁详情页 */
/* 详情页铺满一屏：头部按内容高度，下方左右两栏吃满剩余高度且等高，右侧面板栏内滚动 */
.threat-detail {
  max-width: none; padding-top: 16px;
  overflow: hidden;
}
.tv-crumb {
  display: flex; align-items: center; gap: 8px; margin-bottom: 12px;
  font-size: 13px; color: var(--muted);
}
.tv-crumb em { font-style: normal; color: var(--ink-2); }
.tv-head {
  display: flex; flex-direction: column; gap: 14px; align-items: stretch;
  background: #fff; border: 1px solid var(--line); border-radius: 12px;
  border-left: 4px solid #ef4444;
  padding: 16px 18px; margin-bottom: 12px; box-shadow: var(--shadow);
}
.tv-head-main { display: flex; gap: 12px; min-width: 0; align-items: flex-start; }
.tv-head-main > div { min-width: 0; flex: 1; }
.tv-warn {
  width: 40px; height: 40px; border-radius: 10px; flex-shrink: 0;
  background: #fef2f2; color: #dc2626; display: grid; place-items: center; font-size: 20px;
}
.tv-head h1 {
  margin: 0; font-size: 18px; font-weight: 700; line-height: 1.35;
  word-break: break-word;
}
.tv-meta {
  display: flex; flex-wrap: wrap; gap: 10px 14px; margin-top: 8px;
  font-size: 12px; color: var(--muted);
}
.tv-head-actions {
  display: flex; gap: 10px 22px; flex-wrap: wrap; align-items: center;
  padding-top: 12px; border-top: 1px dashed var(--line);
}
.tv-act-group { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.tv-act-label { font-size: 11px; font-weight: 700; color: var(--muted); letter-spacing: .05em; margin-right: 2px; }
.cmd-st {
  display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 650;
  background: #f2f4f7; color: #667085;
}
.cmd-st[data-s="pending"], .cmd-st[data-s="sent"] { background: #fffaeb; color: #b54708; }
.cmd-st[data-s="done"] { background: #ecfdf3; color: #027a48; }
.cmd-st[data-s="failed"] { background: #fef3f2; color: #b42318; }
.tab-n {
  display: inline-grid; place-items: center; min-width: 16px; height: 16px; margin-left: 4px;
  padding: 0 4px; border-radius: 999px; background: #f79009; color: #fff;
  font-size: 10px; font-style: normal; font-weight: 700;
}
.tv-tabs {
  display: flex; gap: 4px; margin-bottom: 12px;
  border-bottom: 1px solid var(--line);
}
.tv-tab {
  border: 0; background: none; padding: 10px 16px; color: var(--muted);
  font-size: 13px; font-weight: 600; border-bottom: 2px solid transparent; margin-bottom: -1px;
}
.tv-tab.on { color: var(--accent); border-bottom-color: var(--accent); }
.tv-body {
  display: grid; grid-template-columns: minmax(0, 1fr) 360px; grid-template-rows: minmax(0, 1fr);
  gap: 12px; align-items: stretch;
  flex: 1 1 auto; min-height: 0;
  overflow: hidden;
}
.tv-body > .tv-canvas { min-height: 0; }
.tv-canvas {
  background: #fff; border: 1px solid var(--line); border-radius: 12px;
  min-height: 0; position: relative; overflow: auto;
  display: flex; flex-direction: column; align-items: stretch; justify-content: flex-start;
  padding: 18px 20px 24px; box-shadow: var(--shadow);
}
/* 威胁图画布：点阵背景 + 内容居中 */
.tv-canvas.graph {
  background-color: #eef2f8;
  background-image:
    radial-gradient(ellipse 80% 50% at 50% 0%, rgba(99,102,241,.08), transparent 55%),
    radial-gradient(#c5cedd 1px, transparent 1px);
  background-size: 100% 100%, 22px 22px;
  align-items: stretch; justify-content: flex-start; padding: 0;
  container-type: inline-size;
}
.tv-graph-banner {
  display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
  padding: 14px 18px; background: rgba(255,255,255,.92); border-bottom: 1px solid var(--line-2);
  backdrop-filter: blur(6px);
}
.tv-graph-banner-l { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.tv-graph-banner-t { font-size: 14px; font-weight: 700; }
.sev.lg { font-size: 12px; padding: 4px 12px; }
.tv-flow-stage {
  flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center;
  padding: 36px 24px 20px; min-height: 280px;
}
.tv-canvas.plain { background: #fafbfd; }
.tv-canvas-tools {
  position: static; display: flex; gap: 8px; flex-wrap: wrap;
}
.chip.soft.atk { background: #eef2ff; color: #3730a3; border: 1px solid #c7d2fe; }
.chip.soft { background: rgba(255,255,255,.9); }
/* 威胁图：横向流程 主机 → 父进程 → 威胁 */
.tv-flow {
  display: flex; align-items: center; justify-content: center; width: 100%; max-width: 980px;
}
.tvf-node {
  flex: 1 1 0; min-width: 150px; max-width: 280px; min-height: 118px;
  background: #fff; border: 1px solid #d7dee9; border-radius: 16px;
  padding: 18px 16px 14px; text-align: center; position: relative;
  box-shadow: 0 8px 24px rgba(15,23,42,.08);
  display: flex; flex-direction: column; align-items: center; gap: 6px;
  border-top: 3px solid #6366f1; transition: transform .15s, box-shadow .15s;
}
.tvf-node:hover { transform: translateY(-2px); box-shadow: 0 10px 26px rgba(16,24,40,.12); }
.tvf-node.proc { border-top-color: #0ea5e9; }
.tvf-node.miss { border-top-color: #f79009; background: #fffbeb; }
.tvf-node.mod { border-top-color: #94a3b8; border-style: dashed; border-top-style: solid; }
.tvf-node.hit {
  border-color: #fca5a5; border-top-color: #ef4444; cursor: pointer;
  background: linear-gradient(180deg, #fff5f5, #fff 60%);
  box-shadow: 0 8px 26px rgba(225,29,46,.18); min-width: 170px;
  flex-grow: 1.5; max-width: 340px;
}
.tvf-node.hit.on { outline: 2px solid #ef4444; outline-offset: 2px; }
.tvf-kind {
  font-size: 11px; font-weight: 700; padding: 2px 10px; border-radius: 999px;
  background: #eef2ff; color: #3730a3;
}
.tvf-node.proc .tvf-kind { background: #e0f2fe; color: #0369a1; }
.tvf-node.miss .tvf-kind { background: #ffedd5; color: #c2410c; }
.tvf-node.mod .tvf-kind { background: #f1f5f9; color: #475569; }
.tvf-node.hit .tvf-kind { background: #fee2e2; color: #b91c1c; }
.tvf-node b {
  display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; line-clamp: 2;
  max-width: 100%; font-size: 15px; font-weight: 700; line-height: 1.3;
  overflow: hidden; overflow-wrap: anywhere;
}
.tvf-node small {
  display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 3; line-clamp: 3;
  max-width: 100%; max-height: 4.2em; color: #334155; font-size: 11.5px; line-height: 1.4;
  overflow: hidden; overflow-wrap: anywhere; word-break: break-all;
}
.tvf-node.hit small { color: #9f1239; }
.tvf-meta { display: flex; flex-wrap: wrap; justify-content: center; gap: 6px; margin-top: 4px; }
.tvf-meta span {
  font-size: 11px; padding: 2px 8px; border-radius: 6px; background: #f1f5f9; color: #334155;
  display: inline-flex; gap: 4px; align-items: center;
}
.tvf-meta span i { font-style: normal; color: var(--muted); }
.tvf-meta span.ok { background: #ecfdf3; color: #027a48; }
.tvf-meta span.warn { background: #fffaeb; color: #b54708; }
.tvf-edge {
  flex: 0 0 88px; position: relative; height: 3px; background: linear-gradient(90deg, #cbd5e1, #94a3b8); margin: 0 4px;
  align-self: center; border-radius: 2px;
}
.tvf-edge::after {
  content: ''; position: absolute; right: -1px; top: -5px;
  border-left: 9px solid #b6c2d4; border-top: 6px solid transparent; border-bottom: 6px solid transparent;
}
.tvf-edge em {
  position: absolute; left: 50%; top: -11px; transform: translateX(-50%);
  font-style: normal; font-size: 11px; font-weight: 600; color: #475569; white-space: nowrap;
  background: #f4f6fa; padding: 0 8px; border-radius: 999px;
}
.tvf-edge.hot { background: #f87171; }
.tvf-edge.hot::after { border-left-color: #f87171; }
.tvf-edge.hot em { color: #b91c1c; }
.tv-graph-foot {
  flex-shrink: 0; width: 100%; box-sizing: border-box;
  padding: 14px 18px 12px; border-top: 1px solid var(--line-2);
  background: rgba(255,255,255,.96);
}
.tvf-rule {
  display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 0;
  width: 100%; max-width: none; margin: 0;
  background: #fff; border: 1px solid var(--line); border-radius: 12px;
  box-shadow: 0 4px 16px rgba(15,23,42,.06); overflow: hidden;
}
.tvf-rule-item {
  padding: 14px 16px; min-width: 0; border-right: 1px solid var(--line-2);
  border-bottom: 1px solid var(--line-2); border-top: 3px solid #e2e8f0;
}
.tvf-rule-item.span2 { grid-column: span 2; }
.tvf-rule-item.span3 { grid-column: span 3; }
.tvf-rule-item.span4 { grid-column: span 4; }
.tvf-rule-item.wide { grid-column: 1 / -1; border-top-color: #6366f1; border-right: 0; }
.tvf-rule-item:nth-child(4) { border-top-color: #f59e0b; }
.tvf-rule-item:nth-child(4n) { border-right: 0; }
.tvf-rule-item:nth-last-child(-n+3) { border-bottom: 0; }
.tvf-rule label { display: block; font-size: 10px; font-weight: 700; letter-spacing: .04em; color: var(--muted); margin-bottom: 6px; text-transform: uppercase; }
.tvf-rule b { display: block; font-size: 13px; font-weight: 650; word-break: break-word; line-height: 1.4; }
.tvf-rule b.mono { font-family: ui-monospace, Consolas, monospace; font-size: 11px; }
.tvf-rule b.judge { color: #b45309; }
.tv-graph-foot .tv-canvas-hint { margin: 10px 0 0; padding: 0; color: var(--muted); font-size: 12px; text-align: center; }

/* 画布较窄时（笔记本 / 侧栏展开）改为竖向流程，避免横向溢出被裁切 */
@container (max-width: 680px) {
  .tv-flow { flex-direction: column; max-width: 360px; }
  .tvf-node { flex: 0 0 auto; width: 100%; max-width: none; min-width: 0; }
  .tvf-edge {
    flex: 0 0 46px; width: 2px; height: auto; margin: 2px 0; align-self: center;
  }
  .tvf-edge::after {
    right: auto; left: -5px; top: auto; bottom: -1px;
    border-left: 6px solid transparent; border-right: 6px solid transparent;
    border-top: 9px solid #b6c2d4; border-bottom: 0;
  }
  .tvf-edge.hot::after { border-top-color: #f87171; border-left-color: transparent; }
  .tvf-edge em { left: 14px; top: 50%; transform: translateY(-50%); background: transparent; }
  .tvf-rule { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .tvf-rule-item.span2, .tvf-rule-item.span3, .tvf-rule-item.span4 { grid-column: span 1; }
  .tvf-rule-item:nth-child(2n) { border-right: 0; }
  .tvf-rule-item.wide { grid-column: 1 / -1; border-right: 0; }
}

/* 证据详情：分组卡片 */
.ev-hero {
  display: flex; justify-content: space-between; gap: 16px; align-items: flex-start;
  margin-bottom: 18px; padding: 14px 16px; border-radius: 12px;
  background: linear-gradient(135deg, #fff7f7, #fff); border: 1px solid #fee2e2;
}
.ev-hero b { display: block; margin: 6px 0 4px; font-size: 16px; line-height: 1.35; }
.ev-hero p { margin: 0; color: var(--muted); font-size: 12.5px; line-height: 1.5; max-width: 720px; }
.ev-hero-tags { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-end; }
.ev-groups { display: flex; flex-direction: column; gap: 22px; }
.ev-group h4 {
  display: flex; align-items: center; gap: 8px; margin: 0 0 10px;
  font-size: 13px; font-weight: 700; color: var(--ink);
}
.ev-group h4 i { width: 4px; height: 14px; border-radius: 2px; background: #94a3b8; }
.ev-group h4 i[data-t="proc"] { background: #0ea5e9; }
.ev-group h4 i[data-t="cmd"] { background: #6366f1; }
.ev-group h4 i[data-t="sig"] { background: #10b981; }
.ev-group h4 i[data-t="net"] { background: #f59e0b; }
.ev-group h4 i[data-t="other"] { background: #94a3b8; }
.ev-group h4 em {
  font-style: normal; font-size: 11px; font-weight: 600; color: var(--muted);
  background: #eef1f6; padding: 1px 8px; border-radius: 999px;
}
.ev-raw { margin-top: 18px; border: 1px solid #e8eef6; border-radius: 10px; background: #f8fafc; }
.ev-raw summary {
  cursor: pointer; padding: 10px 14px; font-size: 12px; font-weight: 700; color: #475569;
}
.ev-raw .raw-detail { margin: 0; border-radius: 0 0 10px 10px; max-height: 360px; }
.ev-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 10px; }
.ev-card {
  position: relative; background: #fff; border: 1px solid var(--line); border-radius: 10px;
  padding: 10px 12px 11px; min-width: 0;
  transition: border-color .15s, box-shadow .15s;
}
.ev-card:hover { border-color: #c7d2fe; box-shadow: 0 4px 12px rgba(99,102,241,.1); }
.ev-card.wide { grid-column: 1 / -1; padding-right: 58px; }
.ev-card label { display: block; font-size: 11px; color: var(--muted); margin-bottom: 5px; font-weight: 600; }
.ev-val { font-size: 13px; font-weight: 600; color: var(--ink); line-height: 1.5; word-break: break-all; }
.ev-card.mono .ev-val { font-family: ui-monospace, Consolas, monospace; font-size: 12px; font-weight: 500; }
.ev-card.wide .ev-val {
  background: #f7f9fc; border-radius: 6px; padding: 7px 10px; max-height: 96px; overflow: auto;
}
.ev-copy {
  position: absolute; top: 8px; right: 10px; border: 1px solid var(--line); background: #fff;
  color: var(--ink-2); font-size: 11px; padding: 2px 8px; border-radius: 6px; cursor: pointer;
}
.ev-copy:hover { color: var(--accent); border-color: var(--accent); }
.ev-badge {
  display: inline-block; padding: 1px 10px; border-radius: 999px; font-size: 12px; font-weight: 700;
  background: #f2f4f7; color: #667085;
}
.ev-badge[data-t="ok"] { background: #ecfdf3; color: #027a48; }
.ev-badge[data-t="warn"] { background: #fffaeb; color: #b54708; }
.ev-badge[data-t="bad"] { background: #fef3f2; color: #b42318; }

.tv-side {
  background: #fff; border: 1px solid var(--line); border-radius: 12px;
  box-shadow: var(--shadow); overflow: auto; min-height: 0;
}
.tvs-hd {
  display: flex; gap: 10px; align-items: center; padding: 14px 16px;
  border-bottom: 1px solid var(--line); position: sticky; top: 0; background: #fff; z-index: 1;
}
.tvs-file {
  width: 36px; height: 36px; border-radius: 10px; background: #fef2f2; color: #dc2626;
  display: grid; place-items: center; font-weight: 800;
}
.tvs-hd b { display: block; font-size: 13px; word-break: break-word; }
.tvs-hd small { color: var(--muted); font-size: 11px; }
.tvs-sec { padding: 12px 16px 14px; border-bottom: 1px solid var(--line-2); }
.tvs-sec h4 { margin: 0 0 10px; font-size: 13px; font-weight: 700; }
.tvs-cmd-block { background: #0f172a; color: #e2e8f0; }
.tvs-cmd-block h4 { color: #94a3b8; }
.tvs-cmd-pre {
  margin: 0; padding: 10px 12px; border-radius: 8px; background: #020617;
  font-size: 11px; line-height: 1.45; white-space: pre-wrap; word-break: break-all;
  max-height: 220px; overflow: auto;
}
.tv-proc-cmd {
  display: -webkit-box; margin-top: 6px; margin-right: 4px; padding-right: 52px;
  font-size: 10.5px; line-height: 1.4; color: #1e293b;
  word-break: break-all; overflow: hidden;
  -webkit-box-orient: vertical; -webkit-line-clamp: 3; line-clamp: 3;
  max-height: 4.2em;
}
.tv-proc-node.hit .tv-proc-cmd { color: #9f1239; }
.evidence-grid.big { padding: 16px; width: 100%; box-sizing: border-box; }
.raw-detail {
  background: #fff; padding: 16px; border-radius: 8px; width: min(720px, 100%);
  font-size: 12px; white-space: pre-wrap; overflow: auto; max-height: 420px;
}

.agent-sync-wrap { margin-bottom: 8px; flex-shrink: 0; }
.agent-sync-bar {
  display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px;
  padding: 8px 12px;
  background: #f8fafc; border: 1px solid var(--line-2); border-radius: 8px;
  font-size: 11px;
}
.agent-sync-wrap .agent-int-panel {
  margin-top: 6px; border-radius: 8px; border: 1px solid var(--line-2);
  max-height: min(72vh, 920px); overflow: auto;
}
.agent-int-intro {
  padding-bottom: 10px; margin-bottom: 10px; border-bottom: 1px solid var(--line-2);
  font-size: 12px; line-height: 1.55;
}
.agent-int-intro .pill.cloud { background: #e0f2fe; color: #0369a1; }
.agent-int-intro code { font-size: 11px; }
.agent-sync-parts {
  margin-bottom: 12px; font-size: 11px;
}
.agent-sync-parts summary {
  cursor: pointer; color: var(--text-2); font-weight: 600; padding: 4px 0;
}
.agent-sync-parts-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 6px;
  margin-top: 8px;
}
.agent-sync-part-cell {
  display: flex; flex-direction: column; gap: 2px; padding: 6px 8px;
  background: #f8fafc; border-radius: 6px; border: 1px solid var(--line-2);
}
.agent-sync-part-cell .part-name { font-weight: 600; font-size: 11px; }
.agent-sync-part-cell code { font-size: 10px; word-break: break-all; }
.agent-int-section { margin-bottom: 16px; }
.agent-int-section-cloud {
  padding-top: 12px; border-top: 1px dashed var(--line-2);
}
.agent-int-hd {
  margin: 0 0 4px; font-size: 13px; font-weight: 700; color: var(--text);
}
.agent-int-grp-hint { margin: 0 0 8px; }
.agent-int-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 10px;
}
.agent-int-cards.compact { grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); }
.agent-int-card {
  display: flex; align-items: flex-start; gap: 12px;
  padding: 10px 12px; border-radius: 10px;
  border: 1px solid var(--line-2); background: #fff;
  transition: border-color .15s, opacity .15s;
}
.agent-int-card.off {
  opacity: 0.62; background: #f8fafc;
}
.agent-int-card-text {
  flex: 1; min-width: 0;
  display: flex; flex-direction: column; gap: 4px;
}
.agent-int-card-title {
  font-size: 12px; font-weight: 600; line-height: 1.45; color: var(--text);
}
.agent-int-card-key {
  font-size: 10px; color: var(--text-3); align-self: flex-start;
  padding: 1px 6px; background: #f1f5f9; border-radius: 4px;
}
.agent-int-switch {
  position: relative; flex-shrink: 0; width: 40px; height: 22px; cursor: pointer;
}
.agent-int-switch input {
  opacity: 0; width: 0; height: 0; position: absolute;
}
.agent-int-switch-ui {
  position: absolute; inset: 0; border-radius: 11px;
  background: #cbd5e1; transition: background .2s;
}
.agent-int-switch-ui::after {
  content: ''; position: absolute; width: 18px; height: 18px; left: 2px; top: 2px;
  border-radius: 50%; background: #fff; transition: transform .2s;
  box-shadow: 0 1px 2px rgba(0,0,0,.12);
}
.agent-int-switch input:checked + .agent-int-switch-ui { background: #2563eb; }
.agent-int-switch input:checked + .agent-int-switch-ui::after { transform: translateX(18px); }
.agent-int-switch input:disabled + .agent-int-switch-ui { opacity: 0.45; cursor: not-allowed; }
.agent-deploy-ref {
  margin-top: 8px; padding-top: 12px; border-top: 1px solid var(--line-2);
  font-size: 12px;
}
.agent-deploy-ref summary {
  cursor: pointer; font-weight: 700; color: var(--text-2); padding: 4px 0;
}
.agent-deploy-body { padding: 8px 0 4px; }
.agent-deploy-cols {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px 20px; margin-bottom: 10px;
}
.agent-deploy-cols h5 { margin: 0 0 6px; font-size: 12px; }
.agent-deploy-cols ul {
  margin: 0; padding-left: 1.1em; line-height: 1.5; color: var(--text-2);
}
.agent-deploy-cols li { margin-bottom: 6px; }
.agent-deploy-cols code { font-size: 10px; }
.agent-sync-rev b { font-size: 12px; }

.rules-subnav {
  display: flex; flex-wrap: wrap; gap: 8px; flex-shrink: 0;
  padding: 4px; margin-bottom: 4px;
  background: #f1f5f9; border-radius: 10px; border: 1px solid var(--line-2);
}
.rules-tab {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 8px 14px; border: 0; border-radius: 8px;
  background: transparent; color: var(--text-2); font-size: 13px; font-weight: 600;
  cursor: pointer; transition: background .15s, color .15s, box-shadow .15s;
}
.rules-tab:hover { background: rgba(255,255,255,.65); color: var(--text); }
.rules-tab.on {
  background: #fff; color: var(--text);
  box-shadow: 0 1px 3px rgba(15,23,42,.08);
}
.rules-tab-meta {
  font-size: 11px; font-weight: 500; color: var(--muted);
  padding: 2px 7px; border-radius: 999px; background: rgba(148,163,184,.18);
}
.rules-tab.on .rules-tab-meta { color: #475569; background: #f1f5f9; }

.mem-yara-layout {
  flex: 1; min-height: 0; display: flex; flex-direction: column; gap: 10px; overflow: hidden;
}
.mem-yara-top {
  flex-shrink: 0; display: grid; gap: 10px;
  grid-template-columns: minmax(0, 1.1fr) minmax(280px, 0.9fr);
  align-items: stretch;
}
@media (max-width: 1100px) { .mem-yara-top { grid-template-columns: 1fr; } }
.mem-yara-stats {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px;
}
@media (max-width: 900px) { .mem-yara-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.mem-yara-stat {
  border: 1px solid #e8eef6; border-radius: 10px; background: #fff; padding: 10px 12px;
  text-align: left;
}
.mem-yara-stat.click { cursor: pointer; }
.mem-yara-stat.click:hover, .mem-yara-stat.click.on { border-color: #93c5fd; background: #f8fbff; }
.mem-yara-stat.accent { border-color: #bfdbfe; }
.mem-yara-stat label { display: block; font-size: 11px; color: var(--muted); margin-bottom: 4px; }
.mem-yara-stat b { font-size: 15px; font-weight: 700; word-break: break-all; }
.mem-yara-toggles {
  display: grid; grid-template-columns: 1fr 1fr; gap: 6px;
  border: 1px solid #e8eef6; border-radius: 10px; background: #fff; padding: 8px;
}
.mem-yara-tog {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  padding: 6px 8px; border-radius: 8px; background: #f8fafc; font-size: 11.5px; font-weight: 600;
}
.mem-yara-tog.off { opacity: .7; }
.mem-yara-tog span {
  min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.mem-yara-switch { flex-shrink: 0; }
.mem-yara-switch i { box-shadow: inset 0 0 0 1px rgba(15, 23, 42, 0.12); }
.mem-yara-subnav {
  display: flex; gap: 4px; padding: 3px; flex-shrink: 0;
  background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 10px; width: fit-content; max-width: 100%;
}
.mem-yara-subnav button {
  border: 0; background: transparent; color: #475569; font-size: 12.5px; font-weight: 650;
  padding: 7px 12px; border-radius: 8px; cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
}
.mem-yara-subnav button.on { background: #fff; color: #1d4ed8; box-shadow: 0 1px 2px rgba(15,23,42,.08); }
.mem-yara-subnav em {
  font-style: normal; font-size: 10px; background: #e2e8f0; color: #334155;
  padding: 1px 6px; border-radius: 999px;
}
.mem-yara-subnav button.on em { background: #dbeafe; color: #1d4ed8; }
.mem-yara-body {
  flex: 1; min-height: 0; display: flex; flex-direction: column; overflow: hidden;
  border: 1px solid #e8eef6; border-radius: 12px; background: #fff;
}
.mem-yara-body.dim { opacity: .78; }
.mem-yara-body.meta { overflow: auto; padding: 14px; }
.mem-yara-toolbar {
  flex-shrink: 0; display: flex; justify-content: space-between; gap: 12px; align-items: flex-start;
  padding: 12px 14px; border-bottom: 1px solid #eef2f7;
}
.mem-yara-toolbar h3 { margin: 0 0 4px; font-size: 14px; }
.mem-yara-toolbar p { margin: 0; font-size: 12px; color: var(--muted); line-height: 1.45; max-width: 48rem; }
.mem-yara-toolbar-actions { display: flex; gap: 8px; flex-shrink: 0; }
.mem-yara-banner {
  margin: 0; padding: 8px 14px; font-size: 12px; color: #92400e; background: #fffbeb; border-bottom: 1px solid #fde68a;
}
.mem-yara-scroll { flex: 1; min-height: 0; overflow: auto; }
.mem-yara-table { width: 100%; border-collapse: collapse; font-size: 12.5px; table-layout: fixed; }
.mem-yara-table th {
  position: sticky; top: 0; z-index: 1; background: #f8fafc; text-align: left;
  padding: 9px 12px; border-bottom: 1px solid #e8eef6; color: var(--muted); font-weight: 650;
}
.mem-yara-table td {
  padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; word-break: break-word;
}
.mem-yara-table tr.row-off td { opacity: 0.55; }
.mem-yara-table tbody tr:hover td { background: #f8fbff; }
.mem-yara-table .mem-yara-str {
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.mem-yara-meta-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px;
}
.mem-yara-meta-grid section {
  border: 1px solid #eef2f7; border-radius: 10px; padding: 12px 14px; background: #fbfdff;
}
.mem-yara-meta-grid h4 {
  margin: 0 0 10px; font-size: 13px; display: flex; align-items: center; gap: 8px;
}
.mem-yara-meta-grid dl { margin: 0; display: grid; gap: 8px; }
.mem-yara-meta-grid dl > div { display: grid; grid-template-columns: 64px minmax(0, 1fr); gap: 8px; font-size: 12.5px; }
.mem-yara-meta-grid dl .full { grid-template-columns: 64px minmax(0, 1fr); }
.mem-yara-meta-grid dt { margin: 0; color: var(--muted); }
.mem-yara-meta-grid dd { margin: 0; word-break: break-word; }
.pill.sm { font-size: 10px; padding: 2px 8px; }

/* 规则管理 */
.rules-layout {
  display: grid; grid-template-columns: 1.2fr .9fr; gap: 14px;
  flex: 1; min-height: 0; overflow: hidden;
}
.rules-page {
  overflow: hidden;
  display: flex; flex-direction: column;
  min-height: 0;
}
.rules-page > .page-hd { flex-shrink: 0; }
.rules-layout > .panel { min-height: 0; }
.rules-layout > .panel.fill .table-scroll { flex: 1; min-height: 0; overflow: auto; }
.rule-editor {
  min-height: 0; overflow: auto; padding: 0 !important;
  display: flex; flex-direction: column;
}
.rule-editor > h3 {
  position: sticky; top: 0; z-index: 3; margin: 0; padding: 16px 20px 12px;
  font-size: 15px; background: #fff; border-bottom: 1px solid var(--line);
}
.rule-editor > .hint,
.rule-editor > template,
.rule-editor > label,
.rule-editor > div,
.rule-editor > p { margin-left: 20px; margin-right: 20px; }
.rule-editor > .hint { margin-top: 12px; }
.rule-editor > .row {
  position: sticky; bottom: 0; z-index: 2;
  margin-bottom: 0; padding: 12px 0 16px;
  background: linear-gradient(180deg, rgba(255,255,255,.82), #fff 28%);
  border-top: 1px solid var(--line);
}
.rules-layout > .panel.fill > .chip-row { flex-shrink: 0; }
.rules-layout.wl-layout { grid-template-columns: minmax(0, 1.25fr) minmax(280px, .75fr); }
.wl-side { overflow: auto; align-self: stretch; }
.wl-help { margin: 0; padding-left: 18px; font-size: 13px; line-height: 1.55; color: var(--ink-2); }
.wl-help li { margin-bottom: 8px; }
.wl-kind-dl { margin: 0; display: flex; flex-direction: column; gap: 8px; }
.wl-kind-dl dt { font-size: 11px; font-weight: 700; color: var(--muted); }
.wl-kind-dl dd { margin: 2px 0 0; font-size: 12px; line-height: 1.45; color: var(--ink-2); }
.rules-layout tbody tr.active td { background: #eef7ff; }
.sensor-source {
  display: flex; align-items: center; gap: 8px; min-height: 34px;
  padding: 6px 10px; border: 1px solid #dbe7f3; border-radius: 8px;
  background: #f7fbff;
}
.sensor-source small { color: var(--muted); font-weight: 500; }
.form-lab { display: block; margin-bottom: 12px; font-size: 12px; font-weight: 600; color: var(--ink-2); }
.form-lab > span { display: block; margin-bottom: 5px; }
.form-row2 { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.field.area { resize: vertical; min-height: 100px; font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
.mod-checks { display: flex; flex-wrap: wrap; gap: 8px 12px; margin-top: 4px; }
.mod-pills, .chip-row { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px; }
.chip-row.sm .chip-btn { font-size: 11.5px; padding: 4px 8px; }
.mod-pill, .chip-btn {
  border: 1px solid #d0d5dd; background: #fff; color: #475569;
  border-radius: 8px; padding: 5px 10px; font-size: 12px; font-weight: 600; cursor: pointer;
}
.mod-pill.on, .chip-btn.on {
  border-color: #1aa6c8; background: #e8f7fb; color: #0b6e84;
}
.seq-explain { margin-bottom: 14px; background: linear-gradient(135deg, #f0f9fc, #fff); border-color: #cfeaf2; }
.seq-explain b { display: block; margin-bottom: 6px; font-size: 13px; color: #0b6e84; }
.seq-explain p { margin: 0; font-size: 13px; color: #475569; line-height: 1.55; }
.seq-step {
  border: 1px solid #e8eef6; border-radius: 10px; padding: 10px 12px; margin-top: 8px; background: #fafbfd;
}
.seq-step header {
  display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;
}
.seq-step header b { font-size: 12px; color: #334155; }
.chk { display: inline-flex; align-items: center; gap: 6px; font-weight: 500; font-size: 13px; color: var(--ink-2); }
.switch {
  position: relative; display: inline-block; width: 36px; height: 20px;
}
.switch input { opacity: 0; width: 0; height: 0; }
.switch i {
  position: absolute; inset: 0; background: #d0d5dd; border-radius: 999px; transition: .15s; cursor: pointer;
}
.switch i::after {
  content: ''; position: absolute; width: 16px; height: 16px; left: 2px; top: 2px;
  background: #fff; border-radius: 50%; transition: .15s;
}
.switch input:checked + i { background: var(--online); }
.switch input:checked + i::after { transform: translateX(16px); }

/* 终端列表美化 */
.host-summary {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-bottom: 14px;
}
.hs {
  background: #fff; border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px;
  display: flex; justify-content: space-between; align-items: center; box-shadow: var(--shadow);
}
.hs span { color: var(--muted); font-size: 12px; }
.hs b { font-size: 20px; font-weight: 700; }
.hs.on b { color: var(--online); }
.hs.off b { color: var(--muted); }
.hs.danger b { color: var(--danger); }
.host-panel { padding: 0; }
.host-table { min-height: 320px; }
.ht-head, .ht-row {
  display: grid;
  grid-template-columns: 1.4fr .7fr 1fr .7fr 1.2fr .6fr .5fr 1.2fr;
  gap: 8px; align-items: center; padding: 12px 16px; font-size: 13px;
}
.ht-head {
  background: #fafbfd; color: var(--muted); font-size: 12px; font-weight: 600;
  border-bottom: 1px solid var(--line);
}
.ht-row { border-bottom: 1px solid var(--line); }
.ht-row:hover { background: #f7f9fc; }
.ht-host { display: flex; align-items: center; gap: 8px; min-width: 0; }
.ht-host b { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.alert-n {
  display: inline-flex; min-width: 18px; justify-content: center;
  padding: 1px 6px; border-radius: 999px; background: #fef2f2; color: #e11d2e;
  font-style: normal; font-size: 12px; font-weight: 700;
}

.chip.attck {
  background: #eef2ff; color: #3730a3; border: 1px solid #c7d2fe; font-size: 11px;
}
.story-pane { gap: 0; }
.story-techs { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
.stech {
  display: inline-flex; align-items: center; max-width: min(100%, 420px);
  padding: 4px 10px; border-radius: 999px; background: #eef2ff; color: #3730a3;
  border: 1px solid #c7d2fe; font-size: 12px; line-height: 1.35; font-weight: 600;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  font-variant-numeric: tabular-nums;
}
.stech.compact { padding: 2px 8px; font-size: 11px; max-width: min(100%, 280px); }
.story-chain { display: flex; flex-direction: column; gap: 0; flex: 1; min-height: 0; overflow: auto; padding-right: 4px; }
.story-node { display: grid; grid-template-columns: 20px minmax(0, 1fr); gap: 10px; }
.sn-axis { display: flex; flex-direction: column; align-items: center; }
.sn-axis .dot {
  width: 10px; height: 10px; border-radius: 50%; background: #64748b; margin-top: 8px; flex: 0 0 auto;
}
.story-node[data-k="threat"] .sn-axis .dot { background: #e11d2e; box-shadow: 0 0 0 3px #fee2e2; }
.sn-axis .line { width: 2px; flex: 1; background: #e2e8f0; margin: 4px 0; }
.sn-body {
  min-width: 0; padding: 8px 12px 14px; margin-bottom: 4px;
  background: #fff; border: 1px solid #e8eef6; border-radius: 10px;
}
.story-node[data-k="threat"] .sn-body { border-color: #fecaca; background: #fffbfb; }
.sn-top {
  display: flex; flex-wrap: wrap; align-items: center; gap: 6px 8px; margin-bottom: 6px;
}
.sn-top time {
  margin-left: auto; color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums;
}
.sn-kind {
  display: inline-flex; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 700;
  background: #f1f5f9; color: #475569;
}
.sn-kind[data-k="threat"] { background: #fee2e2; color: #b91c1c; }
.sn-title {
  margin: 0; font-size: 13px; font-weight: 650; line-height: 1.4; word-break: break-word;
}
.sn-meta {
  display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px;
}
.sn-meta > span {
  display: inline-flex; gap: 4px; max-width: 100%; padding: 2px 8px; border-radius: 6px;
  background: #f8fafc; border: 1px solid #eef2f7; font-size: 11px; color: var(--ink-2);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.sn-meta em { font-style: normal; color: #98a2b3; font-weight: 600; }
.attck-page { overflow: hidden; gap: 10px; display: flex; flex-direction: column; }
.attck-page > .page-hd { margin-bottom: 0; flex-shrink: 0; }
.attck-page .ak-kpis { flex-shrink: 0; }
.attck-page .ak-board {
  flex: 0 0 auto; display: flex; flex-direction: column; gap: 10px; min-height: 0;
}
.attck-page .attck-recent {
  flex: 1 1 auto; min-height: 180px; display: flex; flex-direction: column; overflow: hidden;
}
.attck-page .attck-recent .table-scroll { flex: 1; min-height: 0; overflow: auto; }
.ak-kpis { grid-template-columns: repeat(5, minmax(0, 1fr)); margin: 0; }
.ak-kpis .kpi-den {
  font-size: 18px; font-weight: 600; color: #98a2b3; margin-left: 2px; letter-spacing: 0;
}
.ak-kpis .c-warn { color: #c2410c; }

.ak-chain { padding-bottom: 12px; }
.ak-steps {
  display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 10px; padding: 4px 16px 12px;
}
.ak-step {
  position: relative; display: flex; flex-direction: column; gap: 8px;
  min-width: 0; padding: 12px 12px 10px; border: 1px solid #e6eaf0; border-radius: 10px;
  background: #fafbfc; text-align: left; cursor: pointer; overflow: hidden;
  transition: border-color .15s, box-shadow .15s, transform .15s;
}
.ak-step::before {
  content: ''; position: absolute; left: 0; right: 0; top: 0; height: 3px; background: #e6eaf0;
}
.ak-step.hit { background: var(--ak-bg, #fff5f5); border-color: rgba(225, 29, 46, .22); }
.ak-step.hit::before { background: var(--ak-bar, #e11d2e); }
.ak-step:hover { border-color: #94a3b8; transform: translateY(-1px); }
.ak-step.on { border-color: #e11d2e; box-shadow: 0 0 0 2px rgba(225, 29, 46, .18); }
.ak-step-top {
  display: flex; align-items: center; gap: 8px; min-width: 0;
}
.ak-no { font-size: 11px; font-weight: 700; color: #a0aab8; letter-spacing: .04em; flex-shrink: 0; }
.ak-step b {
  font-size: 13px; font-weight: 650; color: var(--ink); min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ak-step-bot {
  display: flex; align-items: baseline; justify-content: space-between; gap: 8px; width: 100%;
}
.ak-step strong { font-size: 22px; line-height: 1; font-weight: 700; color: #c0c8d4; }
.ak-step.hit strong { color: #b4141f; }
.ak-step em {
  font-style: normal; font-size: 11.5px; color: #98a2b3; min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: right;
}
.ak-step.hit em { color: #7a2a30; }

.ak-mid {
  display: grid; grid-template-columns: minmax(0, 1.6fr) minmax(260px, 1fr); gap: 10px; align-items: stretch;
  min-height: 220px; max-height: 280px;
}
.ak-mid > .panel { display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
.ak-tech-list {
  display: flex; flex-direction: column; gap: 2px; padding: 4px 12px 14px; flex: 1; min-height: 0; overflow: auto;
}
.ak-tech-row {
  display: grid; grid-template-columns: 72px minmax(0, 1.2fr) minmax(64px, .7fr) minmax(60px, 1fr) 36px;
  align-items: center; gap: 10px; padding: 9px 8px; border: 0; border-radius: 8px;
  background: transparent; text-align: left; cursor: pointer;
}
.ak-tech-row:hover { background: #f8fafc; }
.ak-tech-row.on { background: #fff1f2; }
.ak-tech-row code {
  font-size: 12px; font-weight: 600; color: #b4141f; background: #fff1f2;
  padding: 2px 6px; border-radius: 6px; justify-self: start;
}
.ak-tech-name {
  font-size: 13px; font-weight: 600; color: var(--ink);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.ak-tac {
  font-size: 12px; color: #667085; background: #f2f4f7; border-radius: 6px; padding: 2px 6px;
  justify-self: start; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%;
}
.ak-tech-row .rank-bar { margin-top: 0; }
.ak-tech-row strong { font-size: 15px; font-weight: 700; text-align: right; color: var(--ink); }
.ak-hosts .attck-rank { flex: 1; min-height: 0; overflow: auto; }

.attck-rank {
  padding: 8px 14px 16px; display: flex; flex-direction: column; gap: 6px;
}
.rank-row {
  display: grid; grid-template-columns: 28px 1fr auto; gap: 10px; align-items: center;
  text-align: left; border: 0; background: transparent; padding: 8px 6px; border-radius: 10px;
  cursor: pointer;
}
.rank-row:hover { background: #f8fafc; }
.rank-row.on { background: #eff8ff; }
.rank-row > em {
  font-style: normal; font-size: 12px; font-weight: 700; color: #98a2b3;
  width: 22px; height: 22px; border-radius: 7px; background: #f2f4f7;
  display: inline-flex; align-items: center; justify-content: center;
}
.rank-row:nth-child(-n+3) > em { background: #fff1f0; color: #c2410c; }
.rank-main { min-width: 0; }
.rank-main b {
  display: block; font-size: 13px; font-weight: 650; color: var(--ink);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.rank-bar {
  display: block; height: 6px; border-radius: 99px; background: #eef2f7; margin-top: 6px; overflow: hidden;
}
.rank-bar > i {
  display: block; height: 100%; border-radius: 99px;
  background: linear-gradient(90deg, #fb7185, #e11d2e);
}
.rank-bar.host > i { background: linear-gradient(90deg, #38bdf8, #0284c7); }
.rank-row strong { font-size: 15px; font-weight: 700; color: var(--ink); min-width: 28px; text-align: right; }

.ak-title { max-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ak-techcell { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: #475467; white-space: nowrap; }
.ak-techcell code {
  font-size: 11.5px; font-weight: 600; color: #b4141f; background: #fff1f2; padding: 1px 5px; border-radius: 5px;
}
.ak-st { font-size: 12px; padding: 2px 8px; border-radius: 99px; background: #fff1f2; color: #b4141f; white-space: nowrap; }
.ak-st[data-s='closed'] { background: #ecfdf3; color: #067647; }
.ak-st[data-s='ignored'] { background: #f2f4f7; color: #667085; }
.notify-results { margin-top: 10px; }
.ioc-lib { margin-bottom: 12px; }
.ioc-lib-row { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; flex-wrap: wrap; }
.ioc-lib-stat { display: flex; gap: 16px; align-items: center; font-size: 13px; }
.ioc-lib-stat .on { color: var(--online); font-weight: 600; }
.ioc-lib-stat .off { color: var(--danger); font-weight: 600; }
.up-hosts {
  max-height: 240px; overflow: auto; display: flex; flex-direction: column; gap: 6px;
  border: 1px solid var(--line); border-radius: 8px; padding: 10px; margin-top: 10px;
}
.up-hosts .chk { justify-content: flex-start; }

.inv-page { overflow: hidden; gap: 10px; }
.hosts-page { overflow: hidden; gap: 0; }
.hosts-page > .page-hd,
.hosts-page > .host-summary { flex-shrink: 0; }
.hosts-page .host-panel {
  flex: 1; min-height: 0; display: flex; flex-direction: column; overflow: hidden;
}
.hosts-page .host-table {
  flex: 1; min-height: 0; overflow: auto;
}
.seq-page { overflow: hidden; }
.seq-page > .page-hd { flex-shrink: 0; }
.seq-page .seq-explain { flex-shrink: 0; }
.seq-page .rules-layout { flex: 1; min-height: 0; }
.timeline-page > .page-hd { flex-shrink: 0; }
.snap-viewbar {
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  margin: 0 0 12px; padding: 0 2px;
}
.snap-viewbar .meta { font-size: 12px; color: #98a2b3; }
.dll-list {
  margin-top: 12px; display: flex; flex-direction: column; gap: 6px;
}
.dll-list > small { color: var(--muted); font-size: 12px; font-weight: 650; }
.dll-row {
  display: grid; grid-template-columns: minmax(100px, 140px) 1fr auto; gap: 8px; align-items: center;
  padding: 7px 10px; border-radius: 8px; background: #f8fafc; border: 1px solid #eef2f7;
  text-align: left; width: 100%; cursor: pointer; color: inherit;
}
.dll-row:hover { border-color: #c7d7f0; background: #f5f8ff; }
.dll-row.hot { background: #fff7ed; border-color: #fed7aa; }
.dll-row.on { border-color: #93c5fd; background: #eff6ff; box-shadow: 0 0 0 1px #bfdbfe; }
.dll-row b { font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dll-row em { font-style: normal; font-size: 11px; color: #667085; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dll-detail {
  margin-top: 4px; padding: 12px; border-radius: 10px;
  border: 1px solid #dbe7f3; background: #fff;
}
.dll-detail h5 { margin: 0 0 10px; font-size: 13px; font-weight: 700; }
.dll-detail .mono { font-family: ui-monospace, Consolas, monospace; font-size: 11.5px; word-break: break-all; }
.inv-top {
  display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; flex-shrink: 0;
  background: #fff; border: 1px solid rgba(15, 23, 42, .06); border-radius: 14px;
  padding: 12px 16px; margin-bottom: 12px; box-shadow: 0 8px 24px rgba(15, 23, 42, .045);
}
.inv-tabs { display: flex; gap: 4px; }
.inv-tab {
  background: #fff; border: 1px solid var(--line); border-radius: 8px;
  padding: 8px 14px; font-weight: 650; color: var(--ink-2);
}
.inv-tab.on { color: #fff; background: #1aa6c8; border-color: #1aa6c8; }
.inv-top-acts { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.inv-saved { margin-top: -4px; flex-shrink: 0; }
.inv-saved h4 { margin: 0 0 8px; font-size: 13px; }
.inv-saved-row {
  width: 100%; display: flex; justify-content: space-between; gap: 12px; text-align: left;
  border: 0; background: #f8fafc; border-radius: 8px; padding: 8px 10px; margin-bottom: 4px;
}
.inv-saved-row:hover { background: var(--accent-soft); }
.inv-filters { padding: 12px 14px; flex-shrink: 0; }
.inv-range-lab { font-size: 12px; color: var(--muted); }
.inv-tab.brand {
  color: var(--ink); font-weight: 700; background: transparent; border-color: transparent;
}
.inv-fg {
  display: grid; grid-template-columns: repeat(3, minmax(140px, 1fr)); gap: 8px 10px; margin-bottom: 10px;
}
.inv-fg-2 { grid-template-columns: repeat(3, minmax(140px, 1fr)); }
.inv-chart-empty { padding: 28px 0; text-align: center; }
.inv-fg label {
  display: flex; flex-direction: column; gap: 4px; font-size: 11px; color: var(--muted); font-weight: 650;
}
.inv-fg select, .inv-fg .field {
  border: 1px solid var(--line); border-radius: 6px; padding: 6px 8px; background: #fff; color: var(--ink); font-size: 12.5px;
}
.inv-fg label.inv-check em {
  display: inline-flex; align-items: center; gap: 6px; font-style: normal; font-size: 12.5px;
  color: var(--ink); font-weight: 550; padding: 6px 0; height: 100%;
}
.inv-search-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.inv-search-row .btn.on { border-color: var(--accent); color: var(--accent); background: #fff7f5; }
.inv-search-row label.inv-hide-noise {
  display: inline-flex; align-items: center; margin: 0; padding: 0 4px;
  white-space: nowrap; cursor: pointer; user-select: none;
}
.inv-search-row label.inv-hide-noise em {
  font-style: normal; font-size: 12px; font-weight: 600; color: var(--ink-2);
}
.inv-search-row label.inv-hide-noise input { margin-right: 6px; }
.inv-more-panel { margin-top: 10px; padding-top: 10px; border-top: 1px dashed var(--line-2); }
.bh-expand {
  display: grid; grid-template-columns: minmax(260px, 320px) minmax(0, 1fr);
  gap: 12px; align-items: start;
}
.bh-expand-card {
  background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px 14px;
  min-width: 0;
}
.bh-expand-main { min-height: 0; }
.bh-expand-hd {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  margin: 0 0 10px; font-size: 12px; font-weight: 700; color: #475569;
}
.bh-expand-kv { margin-top: 4px; }
.bh-field-grid {
  display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px;
}
.bh-field {
  min-width: 0; padding: 8px 10px; border-radius: 8px; background: #f8fafc; border: 1px solid #eef2f7;
}
.bh-field.wide { grid-column: 1 / -1; }
.bh-field.root b { color: #b45309; }
.bh-field span {
  display: block; font-size: 11px; color: #98a2b3; font-weight: 650; margin-bottom: 4px;
}
.bh-field b {
  display: block; font-size: 12.5px; font-weight: 650; line-height: 1.45;
  word-break: break-word; overflow-wrap: anywhere;
}
@media (max-width: 1100px) {
  .bh-expand { grid-template-columns: 1fr; }
  .bh-field-grid { grid-template-columns: 1fr; }
}
.tv-tree-bar {
  display: flex; flex-wrap: wrap; gap: 14px; align-items: center;
  padding: 10px 18px; background: rgba(255,255,255,.92); border-bottom: 1px solid var(--line-2);
}
.tv-tree-opt { font-size: 12px; color: var(--muted); display: inline-flex; align-items: center; gap: 6px; }
.tv-drop-chain {
  margin: 0 18px 12px; padding: 14px 16px 16px;
  background: linear-gradient(180deg, #f8fafc, #fff 40%);
  border: 1px solid #dbeafe; border-radius: 14px;
  box-shadow: 0 6px 20px rgba(15,23,42,.06);
}
.tv-drop-head { display: flex; flex-wrap: wrap; gap: 10px; align-items: baseline; margin-bottom: 12px; }
.tv-drop-title { font-size: 13px; font-weight: 700; }
.tv-drop-row { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; }
.tv-drop-node {
  flex: 0 1 auto; min-width: 118px; max-width: 210px;
  padding: 10px 12px; border-radius: 10px; background: #f8fafc;
  border: 1px solid #e2e8f0; text-align: center;
}
.tv-drop-node.file { border-top: 3px solid #8b5cf6; background: #faf5ff; }
.tv-drop-node.proc.parent { border-top: 3px solid #0ea5e9; }
.tv-drop-node.proc.child { border-top: 3px solid #22c55e; }
.tv-drop-node.proc.hit {
  border-color: #f87171; border-top-color: #ef4444;
  background: linear-gradient(180deg, #fff5f5, #fff 70%); cursor: pointer;
}
.tv-drop-kind {
  display: inline-block; font-size: 10px; font-weight: 700; padding: 1px 8px; border-radius: 999px;
  background: #e2e8f0; color: #475569; margin-bottom: 4px;
}
.tv-drop-node.file .tv-drop-kind { background: #ede9fe; color: #5b21b6; }
.tv-drop-node.hit .tv-drop-kind { background: #fee2e2; color: #b91c1c; }
.tv-drop-node b {
  display: block; font-size: 13px; font-weight: 700; line-height: 1.25;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.tv-drop-node small { display: block; margin-top: 4px; font-size: 11px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tv-drop-edge {
  flex: 0 0 72px; position: relative; height: 3px; align-self: center;
}
.tv-drop-edge .line {
  display: block; width: 100%; height: 3px; border-radius: 2px;
  background: linear-gradient(90deg, #94a3b8, #64748b);
}
.tv-drop-edge::after {
  content: ''; position: absolute; right: -1px; top: -5px;
  border-left: 9px solid #64748b; border-top: 6px solid transparent; border-bottom: 6px solid transparent;
}
.tv-drop-edge em {
  position: absolute; left: 50%; top: -13px; transform: translateX(-50%);
  font-style: normal; font-size: 10px; font-weight: 700; color: #334155; white-space: nowrap;
  background: #f1f5f9; padding: 2px 8px; border-radius: 999px; border: 1px solid #e2e8f0;
}
.tv-graph-wrap {
  position: relative; flex: 1; min-height: 360px; display: flex; overflow: hidden;
  background: linear-gradient(180deg, #f1f5f9 0%, #f8fafc 48%, #fff 100%);
}
.tv-graph-stage {
  flex: 1; min-width: 0; overflow: auto; padding: 18px 20px 20px;
  transform-origin: top left; display: flex; flex-direction: column; align-items: stretch;
}
.tv-graph-stage .tv-graph-scroll {
  margin-left: auto; margin-right: auto;
}
.tv-graph-host {
  display: inline-flex; align-items: center; gap: 12px; margin-bottom: 16px;
  padding: 12px 16px; border-radius: 14px;
  background: linear-gradient(135deg, #fff7ed, #fff);
  border: 1px solid #fdba74; box-shadow: 0 4px 16px rgba(249,115,22,.12);
}
.tv-graph-host b { display: block; font-size: 14px; }
.tv-graph-host small { color: var(--muted); font-size: 12px; }
.tv-graph-scroll {
  position: relative; min-width: 100%;
  border-radius: 16px; border: 1px solid #e2e8f0;
  background-color: #fff;
  background-image: radial-gradient(circle, #cbd5e1 1px, transparent 1px);
  background-size: 22px 22px;
  box-shadow: inset 0 0 0 1px rgba(255,255,255,.8);
}
.tv-graph-svg { position: absolute; inset: 0; pointer-events: none; z-index: 0; overflow: visible; }
.tv-graph-edge { filter: drop-shadow(0 1px 1px rgba(15,23,42,.08)); }
.tv-graph-edge.hot { stroke-width: 3; }
.tv-graph-cols {
  position: relative; z-index: 1; display: flex; flex-direction: row; align-items: flex-start;
  min-height: 100%; padding: 4px 0;
}
.tv-graph-col { position: relative; flex-shrink: 0; min-height: 80px; }
.tv-proc-node {
  position: absolute; z-index: 2; box-sizing: border-box;
  padding: 12px 14px 28px 40px; border-radius: 14px; background: #fff;
  border: 1px solid #cbd5e1; border-left: 4px solid #38bdf8;
  box-shadow: 0 8px 22px rgba(15,23,42,.1);
  cursor: default; transition: box-shadow .15s, transform .15s, border-color .15s;
  overflow: hidden;
}
.tv-proc-node.readable { padding-left: 38px; }
.tv-proc-node:hover { transform: translateY(-1px); box-shadow: 0 8px 22px rgba(15,23,42,.12); }
.tv-proc-node.hit {
  border-color: #fca5a5; border-left-color: #ef4444;
  background: linear-gradient(180deg, #fff5f5, #fff 65%);
  box-shadow: 0 10px 28px rgba(239,68,68,.18); cursor: pointer;
}
.tv-proc-node.hit.on { outline: 2px solid #ef4444; outline-offset: 2px; }
.tv-proc-node.missing {
  border-style: dashed; background: #fffbeb; border-color: #fdba74; border-left-color: #f97316;
}
.tv-proc-node.missing b { color: #9a3412; }
.tv-proc-node b {
  display: block; font-size: 13px; font-weight: 700; line-height: 1.3;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.tv-proc-node small { display: block; margin-top: 2px; font-size: 11px; color: var(--muted); }
.tv-proc-ico {
  position: absolute; left: 10px; top: 12px; width: 22px; height: 22px; border-radius: 6px;
  background: #eff6ff; color: #2563eb; font-size: 12px; display: flex; align-items: center; justify-content: center;
}
.tv-proc-ico.host { position: static; width: 28px; height: 28px; font-size: 14px; }
.tv-proc-fold {
  position: absolute; right: 8px; top: 8px; width: 20px; height: 20px; border-radius: 6px;
  border: 1px solid var(--line); background: #fff; font-size: 13px; line-height: 1; cursor: pointer;
}
.tv-hit-tag {
  position: absolute; right: 8px; bottom: 8px; font-style: normal; font-size: 10px;
  padding: 2px 7px; border-radius: 999px; background: #fee2e2; color: #b91c1c; font-weight: 700;
  z-index: 1; pointer-events: none;
}
.tv-graph-tools {
  position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
  display: flex; flex-direction: column; gap: 6px; z-index: 5;
}
.tv-graph-tools button {
  width: 34px; height: 34px; border-radius: 8px; border: 1px solid var(--line);
  background: #fff; box-shadow: 0 4px 12px rgba(15,23,42,.08); cursor: pointer; font-size: 16px;
}
.inv-chart { padding: 10px 14px 6px; flex-shrink: 0; }
.inv-chart-hd {
  display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;
  font-size: 12px; font-weight: 650;
}
.inv-legend { display: flex; gap: 12px; align-items: center; font-size: 12px; color: var(--muted); font-weight: 500; }
.inv-legend i {
  display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 4px; vertical-align: middle;
}
.inv-legend i[data-n="threat"] { background: #e11d2e; }
.inv-legend i[data-n="risk"] { background: #f79009; }
.inv-legend i[data-n="minor"] { background: #1aa6c8; }
.inv-bars {
  display: flex; align-items: flex-end; gap: 2px; height: 72px; overflow-x: auto; padding-bottom: 2px;
}
.inv-bar-col { flex: 1 0 14px; min-width: 10px; height: 100%; display: flex; flex-direction: column; align-items: center; }
.inv-bar-stack {
  flex: 1; width: 100%; max-width: 18px; display: flex; flex-direction: column-reverse;
  justify-content: flex-start; border-radius: 2px 2px 0 0; overflow: hidden; background: #eef2f7;
}
.inv-bar-stack .seg { width: 100%; display: block; min-height: 0; }
.inv-bar-stack .seg.threat { background: #e11d2e; }
.inv-bar-stack .seg.risk { background: #f79009; }
.inv-bar-stack .seg.minor { background: #1aa6c8; }
.inv-bar-col em { font-style: normal; font-size: 9px; color: #98a2b3; margin-top: 2px; white-space: nowrap; }
.inv-body { display: flex; flex-direction: column; min-height: 0; flex: 1; overflow: hidden; }
.inv-cats {
  display: flex; gap: 0; border-bottom: 1px solid var(--line); padding: 0 8px; flex-shrink: 0;
}
.inv-cats button {
  border: 0; background: none; padding: 12px 14px; font-size: 13px; font-weight: 600; color: var(--muted);
  border-bottom: 2px solid transparent; margin-bottom: -1px;
}
.inv-cats button.on { color: #e11d2e; border-bottom-color: #e11d2e; }
.inv-bars { height: 120px; }
.inv-cats em { font-style: normal; margin-left: 4px; color: #98a2b3; font-variant-numeric: tabular-nums; }
.inv-layout { display: grid; grid-template-columns: 1fr; min-height: 0; flex: 1; overflow: hidden; }
.inv-layout.open { grid-template-columns: minmax(0, 1.35fr) minmax(360px, .85fr); }
.inv-list {
  display: flex; flex-direction: column; min-height: 0; min-width: 0;
  overflow: hidden; background: #fff;
}
.inv-list-scroll { flex: 1; min-height: 0; overflow: auto; }
.inv-list .list-pager { flex-shrink: 0; }
.inv-busy-hint { margin: 0 0 8px; padding: 0 4px; }
.inv-list-scroll.dim { opacity: 0.55; pointer-events: none; }
.inv-list .empty, .inv-list .ov-empty { margin: auto; padding: 48px 24px; text-align: center; }
.inv-list table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.inv-list th {
  text-align: left; padding: 9px 12px; background: #f5f8fc; border-bottom: 1px solid var(--line);
  color: var(--muted); font-weight: 650; position: sticky; top: 0; z-index: 1;
}
.inv-list td { padding: 8px 12px; border-bottom: 1px solid #eef2f7; vertical-align: middle; }
.inv-list tr:hover td { background: #f8fafc; }
.inv-list tr.active td { background: #e8f6fb; }
.list-pager {
  display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
  padding: 10px 14px; border-top: 1px solid #e8eef6;
  background: linear-gradient(180deg, #fafbfd 0%, #f5f8fc 100%);
}
.list-pager .pg-info {
  font-size: 12.5px; color: #667085; font-weight: 550;
  font-variant-numeric: tabular-nums;
}
.list-pager .pg-acts { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.list-pager .pg-size {
  border: 1px solid #e4eaf3; border-radius: 8px; background: #fff;
  padding: 5px 10px; font-size: 12px; color: var(--ink-2); min-width: 96px;
  cursor: pointer;
}
.list-pager .pg-size:hover { border-color: #c7d7f0; }
.list-pager .btn.sm:disabled {
  opacity: .45; cursor: not-allowed; background: #f1f5f9; color: #98a2b3;
}
.list-pager .btn.sm {
  min-width: 68px; border-radius: 8px; font-weight: 600;
}
.nat {
  display: inline-flex; padding: 1px 7px; border-radius: 6px; font-size: 11px; font-weight: 700;
  background: #f1f5f9; color: #475569;
}
.nat[data-n="threat"] { background: #fee2e2; color: #b91c1c; }
.nat[data-n="risk"] { background: #fff7ed; color: #c2410c; }
.nat[data-n="surface"] { background: #f3e8ff; color: #7e22ce; }
.nat[data-n="minor"] { background: #e0f2fe; color: #0369a1; }
.inv-detail {
  border-left: 1px solid var(--line); background: #fff;
  display: flex; flex-direction: column; min-height: 0; overflow: hidden;
}
.inv-dh {
  display: flex; justify-content: space-between; gap: 10px; padding: 14px 16px 12px;
  border-bottom: 1px solid var(--line); flex-shrink: 0; background: linear-gradient(180deg, #f8fafc, #fff);
}
.inv-dh b { display: block; font-size: 14px; line-height: 1.4; font-weight: 700; }
.inv-dh small { color: var(--muted); font-size: 12px; }
.inv-dtabs {
  display: flex; gap: 2px; padding: 0 12px; border-bottom: 1px solid var(--line); flex-shrink: 0; background: #fff;
}
.inv-dtabs button {
  border: 0; background: none; padding: 11px 14px; font-size: 13px; font-weight: 600; color: var(--muted);
  border-bottom: 2px solid transparent; margin-bottom: -1px;
}
.inv-dtabs button.on { color: #c56a00; border-bottom-color: #e67e22; }
.inv-dbody { padding: 14px 16px 18px; overflow: auto; flex: 1; min-height: 0; background: #f7f9fc; }
.inv-g {
  margin-bottom: 12px; background: #fff; border: 1px solid #e8eef6; border-radius: 10px;
  padding: 12px 14px; box-shadow: 0 1px 2px rgba(15,30,55,.03);
}
.inv-g h5 {
  margin: 0 0 10px; font-size: 12px; color: #475569; font-weight: 700;
  letter-spacing: .02em; padding-bottom: 8px; border-bottom: 1px dashed #e8eef6;
}
.inv-kv { display: flex; flex-direction: column; gap: 0; }
.inv-kv-row {
  display: grid; grid-template-columns: 100px minmax(0, 1fr); gap: 10px; align-items: start;
  padding: 8px 0; border-bottom: 1px solid #f1f5f9;
}
.inv-kv-row:last-child { border-bottom: 0; padding-bottom: 0; }
.inv-kv-row.wide { grid-template-columns: 1fr; gap: 4px; }
.inv-kv-row > span { color: #98a2b3; font-size: 12px; font-weight: 600; padding-top: 1px; }
.inv-kv-row > strong {
  font-size: 13px; font-weight: 550; color: var(--ink); word-break: break-all;
  display: flex; gap: 8px; align-items: flex-start; line-height: 1.45;
}
.inv-dacts { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 4px; }
.attck-recent { margin-top: 0; }
.attck-recent .panel-hd { align-items: flex-end; }
.attck-recent table { width: 100%; border-collapse: collapse; font-size: 13px; }
.attck-recent th {
  text-align: left; padding: 10px 12px; background: #fafbfd; border-bottom: 1px solid var(--line);
  color: var(--muted); font-weight: 650; font-size: 12px;
}
.attck-recent td { padding: 10px 12px; border-bottom: 1px solid #eef2f7; vertical-align: middle; }
.attck-recent tr:hover td { background: #f8fafc; }
.inv-chain { display: flex; flex-direction: column; gap: 0; }
.inv-cnode {
  display: grid; grid-template-columns: 16px 1fr; gap: 10px; padding: 10px 8px;
  border-left: 2px solid #e2e8f0; margin-left: 6px; position: relative;
}
.inv-cnode .dot {
  width: 10px; height: 10px; border-radius: 50%; background: #94a3b8; margin-top: 4px;
  box-shadow: 0 0 0 3px #f1f5f9;
}
.inv-cnode.on { background: #fff7ed; border-radius: 8px; border-left-color: #e67e22; }
.inv-cnode.on .dot { background: #e67e22; box-shadow: 0 0 0 3px #ffedd5; }
.inv-cnode.miss { opacity: .7; }
.inv-cnode b { display: block; font-size: 13px; }
.inv-cnode span { font-size: 12px; color: var(--muted); }
.inv-cnode small { display: block; font-size: 11px; color: #667085; margin-top: 2px; word-break: break-all; }
.inv-raw {
  margin: 0 0 10px; padding: 12px; background: #0f1724; color: #e2e8f0; border-radius: 8px;
  font-size: 11.5px; line-height: 1.45; overflow: auto; max-height: 480px; white-space: pre-wrap; word-break: break-all;
}

@media (max-width: 1280px) {
  .ak-steps { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .ak-mid { max-height: none; }
}

@media (max-width: 1100px) {
  .app { grid-template-columns: 68px 1fr; }
  .menu { left: 68px; width: 200px; }
  .workspace.menu-pinned { padding-left: 0; }
  .ov-kpis, .ov-kpis-4, .focus-grid, .host-summary, .attck-bottom { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ov-body { grid-template-columns: 1fr; }
  .settings-page { overflow: auto; }
  .settings-rules-panel { min-height: 320px; }
  .ak-kpis { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .ak-mid { grid-template-columns: 1fr; max-height: none; }
  .ak-steps { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .ov-grid, .ov-body, .event-layout, .deploy-grid, .tv-body, .snap-work, .inv-layout.open, .inv-fg { grid-template-columns: 1fr; }
  .tv-side, .snap-detail { position: static; max-height: none; }
  .tv-body { grid-template-rows: auto; flex: none; min-height: 0; }
  .tv-body > .tv-canvas { min-height: 480px; }
  .tvf-rule { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .tvf-rule-item.span2, .tvf-rule-item.span3, .tvf-rule-item.span4 { grid-column: span 1; }
  .tvf-rule > div:nth-child(2) { border-right: 0; }
  .ht-head, .ht-row { grid-template-columns: 1.2fr 1fr .7fr 1fr; }
  .ht-head span:nth-child(n+5), .ht-row span:nth-child(n+5) { display: none; }
  .ht-row .ops { display: flex !important; }
}
@media (min-width: 861px) and (max-width: 1100px) {
  .rules-layout { grid-template-columns: minmax(0, 1.15fr) minmax(360px, .85fr); }
}
@media (max-width: 860px) {
  .rules-page { overflow: auto; }
  .mem-yara-layout { overflow: visible; }
  .rules-layout { grid-template-columns: 1fr; overflow: visible; }
  .rules-layout > .panel.fill { max-height: 58vh; min-height: 360px; }
  .rule-editor { max-height: none; overflow: visible; }
  .split { grid-template-columns: 1fr; }
  .term-pane { max-height: 220px; }
}
.ai-page {
  display: flex; flex-direction: column; min-height: 0; gap: 10px;
  overflow: hidden; /* 吃满视口，空白交给下方列表撑开 */
}
.ai-page > .page-hd { flex-shrink: 0; margin-bottom: 0; }
.ai-status-bar {
  display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px 16px;
  align-items: center; font-size: 12px; flex-shrink: 0;
}
.ai-status-main { display: flex; flex-wrap: wrap; gap: 8px 12px; align-items: center; }
.ai-status-skills { font-size: 11px; }
.ai-layout {
  flex: 1 1 auto; min-height: 0;
  display: grid; grid-template-columns: minmax(280px, 360px) minmax(0, 1fr); gap: 12px;
}
.ai-host-pane, .ai-result-pane {
  min-height: 0; display: flex; flex-direction: column; overflow: hidden;
}
.ai-host-pane .panel-hd, .ai-result-pane .panel-hd {
  display: flex; justify-content: space-between; align-items: center; gap: 8px;
  padding: 12px 14px; border-bottom: 1px solid var(--line); flex-shrink: 0;
}
.ai-host-pane .panel-hd.tight { padding-top: 8px; padding-bottom: 6px; }
.ai-host-pane h3 em { font-style: normal; color: var(--muted); margin-left: 4px; }
.ai-only-online { font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 4px; }
.ai-host-list { flex: 1; min-height: 0; overflow: auto; padding: 8px; }
.ai-host-row {
  width: 100%; display: flex; align-items: center; gap: 10px; text-align: left;
  border: 1px solid transparent; background: #fff; border-radius: 10px; padding: 10px 12px;
  cursor: pointer; margin-bottom: 6px;
}
.ai-host-row:hover { background: #f8fafc; border-color: var(--line-2); }
.ai-host-row.on { background: #eff6ff; border-color: #93c5fd; }
.ai-host-row.offline { opacity: .72; }
.ai-host-dot {
  width: 8px; height: 8px; border-radius: 50%; background: #cbd5e1; flex-shrink: 0;
}
.ai-host-dot.on { background: #16a34a; box-shadow: 0 0 0 3px rgba(22,163,74,.15); }
.ai-host-meta { flex: 1; min-width: 0; }
.ai-host-meta b { display: block; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ai-host-meta small { color: var(--muted); font-size: 11px; }
.ai-host-badges em { font-style: normal; }
.ai-skill-box { border-top: 1px solid var(--line); padding: 0 8px 10px; flex-shrink: 0; max-height: 260px; overflow: auto; }
.ai-skill-matched { display: flex; flex-direction: column; gap: 6px; padding: 4px 6px 8px; }
.ai-skill-hit { display: grid; gap: 2px; }
.ai-skill-hit small { font-size: 10.5px; color: var(--muted); line-height: 1.35; padding-left: 2px; }
.ai-skill-matched .chip.on {
  background: #dbeafe; color: #1d4ed8; border-color: #93c5fd; font-weight: 650;
  justify-self: start;
}
.ai-skill-matched .chip em {
  font-style: normal; margin-left: 4px; font-size: 10px; opacity: .75;
}
.ai-skill-chips { display: flex; flex-wrap: wrap; gap: 6px; padding: 0 6px 6px; }
.ai-skill-chips .chip.dim { opacity: .35; }
.ai-skill-chips .chip.pri { border-color: #93c5fd; background: #eff6ff; }
.ai-result-body {
  flex: 1; min-height: 0; overflow: hidden;
  padding: 12px 14px 12px;
  display: flex; flex-direction: column; gap: 10px;
}
.ai-tabs {
  display: flex; flex-wrap: wrap; gap: 4px; margin: 0; padding: 3px;
  background: #f1f5f9; border-radius: 10px; border: 1px solid #e2e8f0;
  flex-shrink: 0;
}
.ai-tabs button {
  border: 0; background: transparent; color: #475569; font-size: 12.5px; font-weight: 600;
  padding: 7px 12px; border-radius: 8px; cursor: pointer; display: inline-flex; align-items: center; gap: 5px;
}
.ai-tabs button:hover { background: #fff; color: #0f172a; }
.ai-tabs button.on { background: #fff; color: #1d4ed8; box-shadow: 0 1px 2px rgba(15,23,42,.08); }
.ai-tabs button em {
  font-style: normal; font-size: 10px; background: #fee2e2; color: #b91c1c;
  padding: 1px 5px; border-radius: 999px; font-weight: 700;
}
.ai-tab-pane {
  flex: 1 1 auto; min-height: 0;
  display: flex; flex-direction: column;
  overflow: hidden;
}
.ai-tab-pane.ai-overview { overflow: auto; }
.ai-hero {
  display: grid; grid-template-columns: minmax(220px, 0.9fr) minmax(0, 1.4fr); gap: 12px;
  margin: 0; align-items: stretch; flex-shrink: 0;
}
.ai-hero-verdict {
  border: 1px solid #e8eef6; border-radius: 12px; padding: 12px 14px; background:
    linear-gradient(135deg, #f8fafc 0%, #eef6ff 100%);
  display: flex; flex-direction: column; gap: 8px; justify-content: center;
}
.ai-hero-meta { display: grid; gap: 2px; }
.ai-hero-meta b { font-size: 16px; }
.ai-hero-meta .sev-严重, .ai-hero-meta .sev-高 { color: #b91c1c; }
.ai-hero-meta .sev-中 { color: #b45309; }
.ai-hero-meta .sev-低 { color: #047857; }
.ai-hero-stats {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px;
}
.ai-hero-stat {
  border: 1px solid #e8eef6; border-radius: 10px; background: #fff; padding: 10px 12px;
  text-align: left; cursor: pointer;
}
.ai-hero-stat:hover { border-color: #93c5fd; background: #f8fbff; }
.ai-hero-stat label { display: block; font-size: 11px; color: var(--muted); margin-bottom: 4px; }
.ai-hero-stat b { font-size: 15px; color: var(--ink); }
.ai-team-strip {
  display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 6px; margin-bottom: 12px;
}
.ai-team-pill {
  display: flex; align-items: center; gap: 8px; border: 1px solid #e8eef6; border-radius: 10px;
  background: #fff; padding: 8px 10px; min-width: 0;
}
.ai-team-pill i {
  width: 7px; height: 7px; border-radius: 50%; background: #16a34a; flex-shrink: 0;
  box-shadow: 0 0 0 3px rgba(22,163,74,.12);
}
.ai-team-pill span { flex: 1; min-width: 0; display: grid; }
.ai-team-pill b { font-size: 11.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ai-team-pill small { font-size: 10.5px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ai-team-pill em { font-style: normal; font-size: 10.5px; color: #027a48; flex-shrink: 0; }
.ai-board {
  display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.85fr); gap: 12px; align-items: start;
}
.ai-board-main, .ai-board-side { display: grid; gap: 12px; }
.ai-panel {
  border: 1px solid #e8eef6; border-radius: 12px; background: #fff; padding: 10px 12px; min-width: 0;
}
.ai-panel-hd {
  display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 8px;
}
.ai-panel-hd h4 { margin: 0; font-size: 12.5px; font-weight: 700; color: #334155; }
.ai-panel-empty { margin: 8px 0; color: var(--muted); font-size: 12.5px; }
.ai-threat-preview { display: grid; gap: 6px; }
.ai-threat-row {
  display: grid; grid-template-columns: auto minmax(0, 1fr) auto; gap: 10px; align-items: start;
  width: 100%; text-align: left; border: 1px solid #eef2f7; border-radius: 10px;
  background: #fbfdff; padding: 8px 10px; cursor: pointer;
}
.ai-threat-row:hover { border-color: #93c5fd; background: #f0f7ff; }
.ai-threat-row-body { min-width: 0; display: grid; gap: 2px; }
.ai-threat-row-body b { font-size: 12.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ai-threat-row-body small {
  font-size: 11.5px; color: var(--muted); line-height: 1.4;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}
.ai-rail { list-style: none; margin: 0; padding: 0; display: grid; gap: 0; }
.ai-rail li {
  display: grid; grid-template-columns: 16px minmax(0, 1fr); gap: 10px;
  padding: 8px 0; border-bottom: 1px dashed #eef2f7;
}
.ai-rail li:last-child { border-bottom: 0; }
.ai-rail-dot {
  width: 9px; height: 9px; border-radius: 50%; margin-top: 5px; background: #94a3b8;
  box-shadow: 0 0 0 3px #e2e8f0; justify-self: center;
}
.ai-rail-dot[data-k="threat"] { background: #dc2626; box-shadow: 0 0 0 3px #fecaca; }
.ai-rail-dot[data-k="log"] { background: #2563eb; box-shadow: 0 0 0 3px #bfdbfe; }
.ai-rail-top { display: flex; align-items: center; gap: 8px; margin-bottom: 2px; }
.ai-rail time { font-size: 11px; color: var(--muted); font-variant-numeric: tabular-nums; }
.ai-rail b { display: block; font-size: 12.5px; line-height: 1.35; }
.ai-rail small { display: block; margin-top: 2px; font-size: 11.5px; color: var(--muted); line-height: 1.4; }
.ai-steps { list-style: none; margin: 0; padding: 0; display: grid; gap: 8px; }
.ai-steps li { display: grid; grid-template-columns: 22px minmax(0, 1fr); gap: 8px; align-items: start; }
.ai-step-no {
  width: 22px; height: 22px; border-radius: 50%; background: #e8f1ff; color: #1d4ed8;
  font-size: 11px; font-weight: 700; display: grid; place-items: center;
}
.ai-steps b { display: block; font-size: 12.5px; }
.ai-steps span, .ai-steps small, .ai-steps em {
  display: block; font-size: 11.5px; color: var(--muted); margin-top: 2px; line-height: 1.4;
}
.ai-steps em { font-style: normal; color: #64748b; }
.ai-meta-compact { margin: 0; display: grid; gap: 6px; }
.ai-meta-compact > div { display: grid; grid-template-columns: 64px minmax(0, 1fr); gap: 6px; font-size: 12px; }
.ai-meta-compact .full { grid-template-columns: 64px minmax(0, 1fr); }
.ai-meta-compact dt { margin: 0; color: var(--muted); }
.ai-meta-compact dd { margin: 0; line-height: 1.4; word-break: break-word; }
.ai-quick-row { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
.ai-quick-row button {
  border: 1px solid #e8eef6; border-radius: 8px; background: #f8fafc; padding: 8px 10px;
  font-size: 12px; cursor: pointer; text-align: left;
}
.ai-quick-row button:hover { background: #eef6ff; border-color: #93c5fd; }
.ai-log-cats, .ai-threats-head + .hint, .ai-tab-pane > .hint { flex-shrink: 0; }
.ai-log-grid {
  flex: 1 1 auto; min-height: 0;
  display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 12px; margin-top: 8px;
  align-items: stretch;
}
.ai-log-grid > div {
  border: 1px solid #e8eef6; border-radius: 10px; padding: 10px; background: #fff;
  min-height: 0; height: 100%; overflow: auto; display: flex; flex-direction: column;
}
.ai-log-grid label {
  display: block; font-size: 12px; font-weight: 650; color: var(--muted); margin-bottom: 8px; flex-shrink: 0;
}
.ai-log-grid .ai-mini-tbl { flex: 1; }
.ai-threats-head {
  display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between;
  gap: 6px 12px; margin-bottom: 8px; flex-shrink: 0;
}
.ai-threats-head label { font-size: 12px; font-weight: 650; color: var(--muted); }
.ai-threats-layout {
  flex: 1 1 auto; min-height: 0;
  display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(260px, 0.9fr); gap: 12px;
  align-items: stretch;
}
.ai-threats-list {
  border: 1px solid #e8eef6; border-radius: 10px; background: #fff;
  overflow: auto; min-height: 0; height: 100%; max-height: none;
}
.ai-threat-title { display: block; font-size: 12.5px; font-weight: 650; }
.ai-threats-list td small { display: block; margin-top: 2px; font-size: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 320px; }
.ai-threat-card {
  border: 1px solid #e8eef6; border-radius: 10px; padding: 12px 14px; background: #fff;
  min-height: 0; height: 100%; overflow: auto; position: static;
}
.ai-threat-card h4 { margin: 0 0 4px; font-size: 14px; line-height: 1.35; }
.ai-threat-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.pill[data-role="关键证据"] { background: #fee2e2; color: #b91c1c; }
.pill[data-role="佐证"] { background: #fffaeb; color: #b54708; }
.pill[data-role="上下文"] { background: #f1f5f9; color: #475569; }
.pill[data-ai="支撑真实攻击"] { background: #fee2e2; color: #b91c1c; }
.pill[data-ai="可疑需复核"] { background: #fffaeb; color: #b54708; }
.pill[data-ai="疑似误报/合规噪音"] { background: #eef2ff; color: #3730a3; }
.pill[data-ai="信息不足"] { background: #f1f5f9; color: #475569; }
.ai-threat-card-top {
  display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap;
}
.ai-threat-card-top b { font-size: 13px; color: #1d4ed8; }
.ai-scope-banner {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: 6px 10px;
  margin: 0; padding: 8px 10px; border-radius: 10px; flex-shrink: 0;
  background: #f8fbff; border: 1px solid #dbeafe; font-size: 12px;
}
.ai-scope-banner b { color: #1e3a8a; }
.ai-scope-banner em { font-style: normal; }
.ai-think-banner {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 12px;
  margin-bottom: 8px; padding: 8px 10px; border-radius: 10px;
  background: #f8fbff; border: 1px solid #dbeafe; flex-shrink: 0;
}
.ai-think-banner b { font-size: 12.5px; color: #1e3a8a; }
.ai-think { flex: 1; min-height: 0; display: flex; flex-direction: column; margin: 0; }
.ai-chain-pane, .ai-logs-pane { overflow: hidden; }
.ai-chain-board {
  flex: 1; min-height: 0; display: flex; flex-direction: column; gap: 12px; overflow: hidden;
}
.ai-chain-flow {
  display: flex; flex-wrap: wrap; align-items: stretch; gap: 8px; flex-shrink: 0;
  padding: 12px; border: 1px solid #e8eef6; border-radius: 12px; background: #fff;
}
.ai-chain-node {
  min-width: 120px; max-width: 180px; flex: 1 1 120px;
  border: 1px solid #e2e8f0; border-radius: 12px; padding: 10px 12px;
  background: #f8fafc; cursor: pointer; display: grid; gap: 2px;
}
.ai-chain-node.host { background: linear-gradient(135deg, #eff6ff, #fff); border-color: #93c5fd; }
.ai-chain-node.stage { background: #fff; }
.ai-chain-node.on { border-color: #2563eb; box-shadow: 0 0 0 2px rgba(37,99,235,.15); }
.ai-chain-node:hover { border-color: #93c5fd; }
.ai-chain-badge {
  width: fit-content; font-size: 10px; font-weight: 700; color: #1d4ed8;
  background: #dbeafe; border-radius: 999px; padding: 1px 7px; margin-bottom: 2px;
}
.ai-chain-node b { font-size: 13px; }
.ai-chain-node small, .ai-chain-node em { font-size: 11px; color: var(--muted); font-style: normal; }
.ai-chain-arrow {
  align-self: center; color: #94a3b8; font-weight: 700; font-size: 16px; flex: 0 0 auto;
}
.ai-chain-detail {
  flex: 1; min-height: 0; overflow: auto; border: 1px solid #e8eef6; border-radius: 12px;
  background: #fff; padding: 12px 14px;
}
.ai-chain-detail header { display: flex; align-items: baseline; gap: 10px; margin-bottom: 10px; }
.ai-chain-detail h4 { margin: 0; font-size: 15px; }
.ai-chain-items { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px; }
.ai-chain-item {
  border: 1px solid #eef2f7; border-radius: 10px; padding: 10px; background: #fbfdff;
}
.ai-chain-item[data-k="threat"] { border-color: #fecaca; background: #fff7f7; }
.ai-chain-item[data-k="log"] { border-color: #bfdbfe; background: #f8fbff; }
.ai-chain-item-top { display: flex; justify-content: space-between; gap: 8px; margin-bottom: 4px; }
.ai-chain-item-top time { font-size: 11px; color: var(--muted); }
.ai-chain-item b { display: block; font-size: 12.5px; margin-bottom: 4px; }
.ai-chain-item p { margin: 0; font-size: 12px; color: #475569; line-height: 1.45; }
.ai-log-cats { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 0 0 8px; flex-shrink: 0; }
.ai-log-cats .chip { cursor: pointer; border: 1px solid #e2e8f0; }
.ai-log-cats .chip.on { background: #dbeafe; color: #1d4ed8; border-color: #93c5fd; font-weight: 650; }
.ai-log-cats .chip.sm { font-size: 11px; padding: 2px 8px; }
.ai-log-board {
  flex: 1; min-height: 0;
  display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(260px, 0.85fr); gap: 12px;
}
.ai-log-main, .ai-log-side {
  min-height: 0; border: 1px solid #e8eef6; border-radius: 12px; background: #fff;
  display: flex; flex-direction: column; overflow: hidden; padding: 10px 12px;
}
.ai-log-table-wrap { flex: 1; min-height: 0; overflow: auto; }
.ai-log-card {
  margin-top: 8px; border-top: 1px solid #eef2f7; padding-top: 8px; flex-shrink: 0;
}
.ai-log-card b { font-size: 13px; }
.ai-log-card p { margin: 4px 0 0; font-size: 12.5px; line-height: 1.45; }
.ai-think-step.llm { background: #f5f3ff; }
.ai-think-step.llm.on { background: #ede9fe; box-shadow: inset 3px 0 0 #7c3aed; }
.ai-evidence-list { margin: 0; padding-left: 16px; }
.ai-evidence-list li {
  font-size: 12px; line-height: 1.45; margin-bottom: 4px;
  padding: 4px 8px; background: #f8fafc; border-radius: 6px; list-style: disc;
}
.ai-mini-tbl .sev-critical, .ai-mini-tbl .sev-高, .ai-mini-tbl .sev-严重 { background: #fee2e2; color: #b91c1c; }
.ai-mini-tbl .sev-high { background: #fee2e2; color: #b91c1c; }
.ai-mini-tbl .sev-medium, .ai-mini-tbl .sev-中 { background: #fffaeb; color: #b54708; }
.ai-mini-tbl .sev-low, .ai-mini-tbl .sev-低 { background: #ecfdf3; color: #027a48; }
.ai-verdict {
  display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 8px;
  font-weight: 700; font-size: 13px; background: #f1f5f9; color: #334155; width: fit-content;
}
.ai-verdict[data-v="真实攻击"] { background: #fee2e2; color: #b91c1c; }
.ai-verdict[data-v="疑似误报"] { background: #fffaeb; color: #b54708; }
.ai-verdict[data-v="信息不足"] { background: #eef2ff; color: #3730a3; }
.ai-disp { margin: 0 0 14px; }
.ai-disp label {
  display: block; font-size: 12px; font-weight: 650; color: var(--muted); margin-bottom: 8px;
}
.ai-section-hd {
  display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between;
  gap: 8px 12px; margin-bottom: 8px; flex-shrink: 0;
}
.ai-section-hd label { font-size: 12.5px; font-weight: 700; color: #334155; margin-right: 8px; }
.ai-report-actions { display: flex; gap: 10px; align-items: center; }
.ai-entity-pane, .ai-report-pane { overflow: hidden; }
.ai-entity-board, .ai-report-board {
  flex: 1 1 auto; min-height: 0;
  display: grid; gap: 12px; align-items: stretch;
}
.ai-entity-board {
  grid-template-columns: minmax(0, 1.15fr) minmax(280px, 1fr);
}
.ai-report-board {
  grid-template-columns: minmax(0, 1.4fr) minmax(260px, 0.85fr);
}
.ai-entity-list {
  border: 1px solid #e8eef6; border-radius: 12px; background: #fff;
  overflow: auto; min-height: 0; padding: 6px;
  display: flex; flex-direction: column; gap: 4px;
}
.ai-entity-row {
  display: grid; grid-template-columns: 64px minmax(0, 1fr) auto; gap: 10px; align-items: start;
  width: 100%; text-align: left; border: 1px solid transparent; border-radius: 10px;
  background: transparent; padding: 9px 10px; cursor: pointer;
}
.ai-entity-row:hover { background: #f8fbff; border-color: #e2e8f0; }
.ai-entity-row.on { background: #eef6ff; border-color: #93c5fd; }
.ai-entity-row[data-risk="malicious"] .ai-entity-type { background: #fee2e2; color: #b91c1c; }
.ai-entity-row[data-risk="suspicious"] .ai-entity-type { background: #fffaeb; color: #b54708; }
.ai-entity-type {
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .02em;
  background: #f1f5f9; color: #475569; border-radius: 7px; padding: 4px 6px; text-align: center;
}
.ai-entity-main { min-width: 0; display: grid; gap: 2px; }
.ai-entity-main b {
  font-size: 12.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.ai-entity-main small {
  font-size: 11.5px; color: var(--muted); line-height: 1.4;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}
.ai-entity-detail {
  border: 1px solid #e8eef6; border-radius: 12px; background: #fff;
  padding: 12px 14px; min-height: 0; overflow: auto;
}
.ai-entity-detail-top {
  display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 8px;
}
.ai-entity-detail-top em { font-style: normal; font-size: 12px; color: var(--muted); }
.ai-entity-detail > h4 {
  margin: 0 0 12px; font-size: 14px; line-height: 1.4; word-break: break-all;
}
.ai-entity-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 10px;
}
.ai-entity-box {
  border: 1px solid #eef2f7; border-radius: 10px; padding: 10px 12px; background: #fbfdff;
}
.ai-entity-box.accent { background: #fff7ed; border-color: #fed7aa; }
.ai-entity-box.advice { background: #f0fdf4; border-color: #bbf7d0; }
.ai-entity-box label {
  display: block; font-size: 11px; font-weight: 700; color: #64748b; margin-bottom: 6px;
}
.ai-entity-box p, .ai-entity-box ol { margin: 0; font-size: 12.5px; line-height: 1.55; }
.ai-entity-box ol { padding-left: 16px; display: grid; gap: 4px; }
.ai-entity-box dl { margin: 0; display: grid; gap: 6px; }
.ai-entity-box dl > div { display: grid; grid-template-columns: 52px minmax(0, 1fr); gap: 6px; font-size: 12px; }
.ai-entity-box dl .full { grid-column: 1 / -1; grid-template-columns: 52px minmax(0, 1fr); }
.ai-entity-box dt { margin: 0; color: var(--muted); }
.ai-entity-box dd { margin: 0; word-break: break-word; }
.ai-ioc-strip { margin-top: 12px; }
.ai-ioc-strip label {
  display: block; font-size: 11px; font-weight: 700; color: #64748b; margin-bottom: 6px;
}
.ai-ioc-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.ai-ioc-chips .chip { max-width: 100%; overflow: hidden; text-overflow: ellipsis; }
.ai-ioc-list { margin: 0; padding-left: 0; list-style: none; display: grid; gap: 6px; }
.ai-ioc-list li { font-size: 12px; word-break: break-all; }
.ai-ioc-list code { font-size: 11.5px; background: #f1f5f9; padding: 1px 5px; border-radius: 4px; }
.ai-panel-empty.fill {
  flex: 1; display: grid; place-items: center; border: 1px dashed #e2e8f0;
  border-radius: 12px; background: #f8fafc; color: var(--muted); font-size: 13px;
}
.ai-report-doc {
  min-height: 0; height: 100%; overflow: auto;
  border: 1px solid #e8eef6; border-radius: 12px; padding: 16px 18px;
  background:
    linear-gradient(#fff, #fff) padding-box,
    linear-gradient(180deg, #eff6ff, #fff) border-box;
}
.ai-report-side {
  min-height: 0; overflow: auto; display: flex; flex-direction: column; gap: 10px;
}
.ai-report-card {
  border: 1px solid #e8eef6; border-radius: 12px; padding: 12px 14px; background: #fff;
}
.ai-report-card label {
  display: block; font-size: 11px; font-weight: 700; color: #64748b; margin-bottom: 6px;
}
.ai-report-card b { display: block; font-size: 16px; margin-bottom: 2px; }
.ai-report-card small { color: var(--muted); font-size: 12px; }
.ai-report-card p, .ai-report-card ul { margin: 0; font-size: 12.5px; line-height: 1.5; }
.ai-report-card ul { padding-left: 16px; display: grid; gap: 4px; }
.ai-report-card.verdict[data-v="真实攻击"] { background: #fef2f2; border-color: #fecaca; }
.ai-report-card.verdict[data-v="真实攻击"] b { color: #b91c1c; }
.ai-report-card.verdict[data-v="疑似误报"] { background: #fffbeb; border-color: #fde68a; }
.ai-report-card.verdict[data-v="疑似误报"] b { color: #b54708; }
.ai-report-card.verdict[data-v="信息不足"] { background: #eef2ff; border-color: #c7d2fe; }
.ai-report-card.verdict[data-v="信息不足"] b { color: #3730a3; }
.ai-mini-tbl { width: 100%; border-collapse: collapse; font-size: 12px; }
.ai-mini-tbl th, .ai-mini-tbl td {
  text-align: left; padding: 6px 8px; border-bottom: 1px solid #eef2f7; vertical-align: top;
}
.ai-mini-tbl th { color: var(--muted); font-weight: 650; background: #f8fafc; }
.ai-mini-tbl td.mono { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ai-mini-tbl .pill[data-risk="malicious"] { background: #fee2e2; color: #b91c1c; }
.ai-mini-tbl .pill[data-risk="suspicious"] { background: #fffaeb; color: #b54708; }
.ai-disp-list { display: grid; gap: 8px; }
.ai-disp-row {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  border: 1px solid #e8eef6; border-radius: 10px; padding: 10px 12px; background: #fff;
}
.ai-disp-row b { display: block; font-size: 13px; }
.ai-disp-row .mono { font-size: 12px; color: #334155; }
.ai-disp-row small { display: block; color: var(--muted); margin-top: 2px; }
.ai-deliv { display: block; color: #64748b; }
.ai-think, .ai-meta, .ai-timeline, .ai-hard { margin: 0 0 14px; }
.ai-think label, .ai-meta label, .ai-timeline label, .ai-hard label {
  display: block; font-size: 12px; font-weight: 650; color: var(--muted); margin-bottom: 8px;
}
.ai-think-layout {
  flex: 1; min-height: 0;
  display: grid; grid-template-columns: minmax(180px, 0.9fr) minmax(0, 1.4fr); gap: 0;
  border: 1px solid #e8eef6; border-radius: 12px; overflow: hidden; background: #fff;
}
.ai-think-steps {
  display: flex; flex-direction: column; gap: 0; border-right: 1px solid #e8eef6; background: #f8fafc;
  max-height: none; height: 100%; overflow: auto; min-height: 0;
}
.ai-think-step {
  text-align: left; border: 0; border-bottom: 1px solid #eef2f7; background: transparent;
  padding: 10px 12px; cursor: pointer;
}
.ai-think-step:hover { background: #eef6ff; }
.ai-think-step.on { background: #e8f1ff; box-shadow: inset 3px 0 0 #2563eb; }
.ai-think-step b { display: block; font-size: 12.5px; color: var(--ink); }
.ai-think-step small { color: var(--muted); font-size: 11px; }
.ai-think-detail { padding: 12px 14px; min-height: 0; height: 100%; overflow: auto; }
.ai-think-detail h4 { margin: 0 0 4px; font-size: 14px; }
.ai-think-block { margin-top: 10px; }
.ai-think-block label {
  display: block; font-size: 11px; font-weight: 700; color: #64748b; margin-bottom: 4px; text-transform: none;
}
.ai-think-block p, .ai-think-block ul { margin: 0; font-size: 12.5px; line-height: 1.55; }
.ai-think-block ul { padding-left: 16px; }
.ai-meta-dl {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px 12px; margin: 0;
  border: 1px solid #e8eef6; border-radius: 10px; padding: 10px 12px; background: #fff;
}
.ai-meta-dl > div { display: grid; grid-template-columns: 72px 1fr; gap: 6px; align-items: start; }
.ai-meta-dl .span2 { grid-column: 1 / -1; }
.ai-meta-dl dt { margin: 0; color: var(--muted); font-size: 12px; }
.ai-meta-dl dd { margin: 0; font-size: 12.5px; }
.ai-mini-tbl tr { cursor: pointer; }
.ai-mini-tbl tr.on td { background: #eef6ff; }
.ai-hard ul { margin: 0; padding-left: 18px; display: grid; gap: 6px; }
.ai-hard li { font-size: 12.5px; }
.ai-hard li b { margin-right: 6px; }
.ai-used-skills { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 12px; }
.ai-used-skills label { font-size: 12px; color: var(--muted); margin-right: 4px; }
.ai-tab-pane:has(.ai-disp) { overflow: auto; }
.ai-md {
  font-size: 13.5px; line-height: 1.7; color: #0f172a;
}
.ai-md h1, .ai-md h2, .ai-md h3 {
  margin: 16px 0 10px; font-size: 15px; font-weight: 700; color: #0f172a;
  padding-bottom: 6px; border-bottom: 1px solid #eef2f7;
}
.ai-md h1 { font-size: 18px; border-bottom-color: #dbeafe; }
.ai-md h2:first-child, .ai-md h1:first-child { margin-top: 0; }
.ai-md p { margin: 0 0 10px; }
.ai-md ul { margin: 0 0 12px; padding-left: 18px; display: grid; gap: 4px; }
.ai-md li { line-height: 1.55; }
.ai-md code {
  font-size: 12px; background: #f1f5f9; padding: 1px 6px; border-radius: 4px;
  border: 1px solid #e2e8f0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
.ai-md strong, .ai-md b { color: #0f172a; }
.ai-extra { margin-top: 12px; font-size: 12px; }
.ai-extra ul { margin: 8px 0 0; padding-left: 18px; }
.ai-busy, .ai-empty {
  flex: 1; min-height: 0; display: grid; place-content: center; gap: 10px;
  text-align: center; padding: 40px 20px; color: var(--muted);
}
.ai-spinner {
  width: 28px; height: 28px; margin: 0 auto; border-radius: 50%;
  border: 3px solid #e2e8f0; border-top-color: #2563eb; animation: ai-spin .8s linear infinite;
}
@keyframes ai-spin { to { transform: rotate(360deg); } }
.pill.ok { background: #ecfdf3; color: #027a48; }
.pill.warn { background: #fffaeb; color: #b54708; }
.pill.danger { background: #fee2e2; color: #b91c1c; }
@media (max-width: 1200px) {
  .ai-team-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .ai-hero { grid-template-columns: 1fr; }
  .ai-hero-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .ai-board { grid-template-columns: 1fr; }
}
@media (max-width: 1100px) {
  .ai-layout { grid-template-columns: 1fr; }
  .ai-think-layout { grid-template-columns: 1fr; }
  .ai-think-steps { border-right: 0; border-bottom: 1px solid #e8eef6; max-height: 180px; }
  .ai-meta-dl { grid-template-columns: 1fr; }
  .ai-log-grid, .ai-log-board, .ai-threats-layout, .ai-entity-board, .ai-report-board { grid-template-columns: 1fr; }
  .ai-threat-card { position: static; }
  .ai-entity-grid { grid-template-columns: 1fr; }
}
</style>
