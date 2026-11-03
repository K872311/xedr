<template>
  <div class="lg">
    <section class="lg-brand">
      <div class="lg-grid" />
      <div class="lg-brand-in">
        <div class="lg-logo">
          <span class="lg-mark">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
          </span>
          <div>
            <strong>EDR 终端安全</strong>
            <em>Endpoint Detection &amp; Response</em>
          </div>
        </div>
        <h1>终端检测与响应<br />管理后台</h1>
        <p class="lg-sub">实时采集 · 威胁检测 · 一键处置，终端风险一屏掌握。</p>
        <ul class="lg-feats">
          <li><i />实时 ETW 进程 / 网络 / 文件监控</li>
          <li><i />IOC 情报匹配与 ATT&amp;CK 战术映射</li>
          <li><i />结束进程、隔离文件、网络隔离与回滚</li>
        </ul>
        <p class="lg-foot">独立部署 · 独立账号 · 与分析平台隔离</p>
      </div>
    </section>

    <section class="lg-side">
      <form v-if="mode === 'login'" class="lg-card" @submit.prevent="doLogin">
        <h2>登录</h2>
        <p class="lg-hint">使用 EDR 后台账号登录</p>
        <label class="lg-field">
          <span>用户名</span>
          <input v-model.trim="username" autocomplete="username" autofocus placeholder="请输入用户名" />
        </label>
        <label class="lg-field">
          <span>密码</span>
          <div class="lg-pw">
            <input v-model="password" :type="showPw ? 'text' : 'password'" autocomplete="current-password" placeholder="请输入密码" />
            <button type="button" class="lg-eye" :title="showPw ? '隐藏密码' : '显示密码'" @click="showPw = !showPw">{{ showPw ? '隐藏' : '显示' }}</button>
          </div>
        </label>
        <p v-if="error" class="lg-err">{{ error }}</p>
        <button class="lg-btn" type="submit" :disabled="busy || !username || !password">
          {{ busy ? '登录中…' : '登 录' }}
        </button>
        <p class="lg-note">忘记密码请联系 EDR 管理员重置</p>
      </form>

      <form v-else class="lg-card" @submit.prevent="doChange">
        <h2>修改初始密码</h2>
        <p class="lg-hint">账号 <b>{{ user?.username }}</b> 首次登录或密码已被重置，需设置新密码后才能进入。</p>
        <label class="lg-field">
          <span>当前密码</span>
          <input v-model="curPw" type="password" autocomplete="current-password" />
        </label>
        <label class="lg-field">
          <span>新密码</span>
          <input v-model="newPw" type="password" autocomplete="new-password" placeholder="至少 8 位，含字母 / 数字 / 符号中两类" />
        </label>
        <label class="lg-field">
          <span>确认新密码</span>
          <input v-model="newPw2" type="password" autocomplete="new-password" />
        </label>
        <p v-if="error" class="lg-err">{{ error }}</p>
        <button class="lg-btn" type="submit" :disabled="busy || !curPw || !newPw || !newPw2">
          {{ busy ? '提交中…' : '保存并进入' }}
        </button>
        <button type="button" class="lg-link" @click="$emit('logout')">换个账号登录</button>
      </form>
    </section>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { edrChangePassword, edrLogin } from './api.js'

const props = defineProps({ user: { type: Object, default: null } })
const emit = defineEmits(['done', 'logout'])

const mode = computed(() => (props.user?.must_change ? 'change' : 'login'))
const username = ref('')
const password = ref('')
const showPw = ref(false)
const curPw = ref('')
const newPw = ref('')
const newPw2 = ref('')
const busy = ref(false)
const error = ref('')

async function doLogin() {
  busy.value = true
  error.value = ''
  try {
    const r = await edrLogin(username.value, password.value)
    curPw.value = password.value
    password.value = ''
    emit('done', r.user)
  } catch (e) {
    error.value = e?.message || '登录失败'
  } finally {
    busy.value = false
  }
}

async function doChange() {
  error.value = ''
  if (newPw.value !== newPw2.value) {
    error.value = '两次输入的新密码不一致'
    return
  }
  busy.value = true
  try {
    const r = await edrChangePassword(curPw.value, newPw.value)
    curPw.value = newPw.value = newPw2.value = ''
    emit('done', r.user)
  } catch (e) {
    error.value = e?.message || '修改失败'
  } finally {
    busy.value = false
  }
}
</script>

<style scoped>
.lg {
  min-height: 100%; display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(400px, 1fr);
  background: #f5f7fb;
}
.lg-brand {
  position: relative; overflow: hidden; color: #c9d6ea;
  background: radial-gradient(1200px 600px at 10% 0%, #1e3a8a 0%, transparent 60%),
              linear-gradient(160deg, #0a101c 0%, #111b2e 55%, #0c1322 100%);
  display: flex; align-items: center;
}
.lg-grid {
  position: absolute; inset: 0; opacity: .35;
  background-image:
    linear-gradient(rgba(148, 163, 184, .08) 1px, transparent 1px),
    linear-gradient(90deg, rgba(148, 163, 184, .08) 1px, transparent 1px);
  background-size: 36px 36px;
  mask-image: radial-gradient(ellipse at 30% 40%, #000 30%, transparent 75%);
}
.lg-brand-in { position: relative; padding: 56px 9%; max-width: 640px; }
.lg-logo { display: flex; align-items: center; gap: 12px; margin-bottom: 56px; }
.lg-mark {
  width: 42px; height: 42px; border-radius: 12px; color: #fff; display: grid; place-items: center;
  background: linear-gradient(145deg, #3b82f6, #1d4ed8); box-shadow: 0 8px 22px rgba(37, 99, 235, .45);
}
.lg-logo strong { display: block; color: #f1f5fb; font-size: 16px; letter-spacing: .02em; }
.lg-logo em { font-style: normal; font-size: 11px; color: #7f93b2; letter-spacing: .06em; }
.lg-brand h1 {
  margin: 0 0 16px; color: #fff; font-size: 38px; line-height: 1.25; font-weight: 750; letter-spacing: .01em;
}
.lg-sub { margin: 0 0 34px; font-size: 15px; color: #9fb0c9; }
.lg-feats { list-style: none; margin: 0 0 56px; padding: 0; display: grid; gap: 14px; }
.lg-feats li { display: flex; align-items: center; gap: 12px; font-size: 14px; color: #cfdaeb; }
.lg-feats i {
  width: 8px; height: 8px; border-radius: 50%; background: #3b82f6; flex: none;
  box-shadow: 0 0 0 4px rgba(59, 130, 246, .18);
}
.lg-foot { margin: 0; font-size: 12px; color: #63779a; letter-spacing: .04em; }

.lg-side { display: grid; place-items: center; padding: 32px; }
.lg-card {
  width: 100%; max-width: 380px; background: #fff; border-radius: 16px; padding: 36px 34px 28px;
  border: 1px solid var(--line); box-shadow: 0 10px 40px rgba(15, 23, 36, .08);
}
.lg-card h2 { margin: 0 0 6px; font-size: 22px; font-weight: 700; }
.lg-hint { margin: 0 0 24px; color: var(--muted); font-size: 13px; }
.lg-field { display: block; margin-bottom: 16px; }
.lg-field > span { display: block; margin-bottom: 6px; font-size: 13px; font-weight: 600; color: var(--ink-2); }
.lg-field input {
  width: 100%; height: 42px; padding: 0 12px; border-radius: 10px; border: 1px solid #d8dfea;
  background: #fbfcfe; outline: none; transition: border-color .15s, box-shadow .15s;
}
.lg-field input:focus { border-color: #3b82f6; background: #fff; box-shadow: 0 0 0 3px rgba(59, 130, 246, .15); }
.lg-pw { position: relative; }
.lg-pw input { padding-right: 56px; }
.lg-eye {
  position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
  border: 0; background: transparent; color: var(--muted); font-size: 12px; padding: 6px 8px;
}
.lg-eye:hover { color: var(--accent); }
.lg-err {
  margin: 0 0 14px; padding: 9px 12px; border-radius: 8px; font-size: 13px;
  background: #fff1f2; color: #be123c; border: 1px solid #fecdd3;
}
.lg-btn {
  width: 100%; height: 44px; border: 0; border-radius: 10px; color: #fff; font-weight: 700; font-size: 15px;
  background: linear-gradient(135deg, #3b82f6, #2563eb); box-shadow: 0 6px 18px rgba(37, 99, 235, .3);
  transition: filter .15s, transform .05s;
}
.lg-btn:hover:not(:disabled) { filter: brightness(1.06); }
.lg-btn:active:not(:disabled) { transform: translateY(1px); }
.lg-btn:disabled { opacity: .55; cursor: not-allowed; box-shadow: none; }
.lg-note { margin: 18px 0 0; text-align: center; font-size: 12px; color: var(--muted); }
.lg-link {
  display: block; margin: 14px auto 0; border: 0; background: transparent; color: var(--muted); font-size: 12px;
}
.lg-link:hover { color: var(--accent); }

@media (max-width: 900px) {
  .lg { grid-template-columns: 1fr; }
  .lg-brand { display: none; }
}
@media (max-width: 480px) {
  .lg-side { padding: 16px; }
  .lg-card { padding: 28px 20px 22px; }
}
</style>
