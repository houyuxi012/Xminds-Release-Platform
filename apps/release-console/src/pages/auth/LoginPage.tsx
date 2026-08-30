import { LockOutlined, SafetyCertificateOutlined, UserOutlined } from '@ant-design/icons';
import { Alert, Button, Card, Form, Input, Space, Spin, Typography } from 'antd';
import { useState } from 'react';
import type { LocalLoginInput, LoginMode } from '../../api/types';
import { useAuth } from '../../auth/AuthProvider';

interface LoginFormValues {
  username: string;
  password: string;
  mfaProof?: string;
}

export function LoginPage() {
  const { status, loginMode, problem, authenticating, login, reloadLoginState } = useAuth();
  const [emergency, setEmergency] = useState(false);

  if (status === 'loading') {
    return (
      <div className="auth-screen" role="status" aria-label="正在加载登录配置">
        <Spin size="large" />
      </div>
    );
  }

  const localAllowed = loginMode === 'local' || loginMode === 'configuring';
  const showForm = emergency || localAllowed;
  const submit = async (values: LoginFormValues) => {
    const input: LocalLoginInput = {
      username: values.username.trim(),
      password: values.password,
      ...(values.mfaProof ? { mfaProof: values.mfaProof.trim() } : {}),
    };
    await login(input, emergency);
  };

  return (
    <main className="auth-screen">
      <section className="auth-brand-panel" aria-labelledby="auth-product-title">
        <div className="auth-brand-mark">X</div>
        <Typography.Title id="auth-product-title" level={1}>
          Xminds Release Platform
        </Typography.Title>
        <Typography.Paragraph>
          面向企业软件交付的可信发布、审批、分发与审计控制台。
        </Typography.Paragraph>
        <ul className="auth-trust-list">
          <li>发布职责分离与高风险操作留痕</li>
          <li>不可变制品、目录摘要与端到端审计</li>
          <li>本地身份与企业 SSO 严格隔离</li>
        </ul>
      </section>

      <Card className="auth-card" variant="borderless">
        <Space orientation="vertical" size={20} className="auth-card-content">
          <div>
            <Typography.Title level={2}>
              {emergency ? '应急管理员登录' : loginHeading(loginMode)}
            </Typography.Title>
            <Typography.Text type="secondary">
              {emergency
                ? '仅用于受控恢复场景，必须使用已登记的 MFA 动态验证码。'
                : loginDescription(loginMode)}
            </Typography.Text>
          </div>
          {loginMode === 'configuring' && !emergency ? (
            <Alert type="warning" showIcon title="企业 SSO 正在配置，本地登录暂时保持可用" />
          ) : null}
          {loginMode === 'fault' && !emergency ? (
            <Alert
              type="error"
              showIcon
              title="普通本地登录保持关闭"
              description="平台不会在身份服务故障时自动降级，避免绕过企业条件访问和离职停用策略。"
            />
          ) : null}
          {loginMode === 'sso' && !emergency ? (
            <Alert
              type="info"
              showIcon
              title="OIDC 登录跳转与回调尚未在当前批次开放"
              description="后端已严格接受当前启用身份源签发的人员令牌；浏览器 Authorization Code + PKCE/BFF 将在下一独立批次接入。"
            />
          ) : null}
          {problem ? (
            <Alert
              type="error"
              showIcon
              title={`${problem.title}${problem.code ? `（${problem.code}）` : ''}`}
              description={problem.request_id ? `请求 ID：${problem.request_id}` : problem.detail}
            />
          ) : null}

          {showForm ? (
            <Form<LoginFormValues>
              layout="vertical"
              requiredMark={false}
              onFinish={submit}
              autoComplete="off"
            >
              <Form.Item
                label="用户名"
                name="username"
                rules={[{ required: true, message: '请输入用户名' }]}
              >
                <Input prefix={<UserOutlined />} autoComplete="username" maxLength={128} />
              </Form.Item>
              <Form.Item
                label="密码"
                name="password"
                rules={[{ required: true, message: '请输入密码' }]}
              >
                <Input.Password
                  prefix={<LockOutlined />}
                  autoComplete="current-password"
                  maxLength={1024}
                />
              </Form.Item>
              <Form.Item
                label={emergency ? 'MFA 动态验证码' : 'MFA 动态验证码（如已启用）'}
                name="mfaProof"
                rules={[
                  ...(emergency
                    ? [{ required: true as const, message: '请输入 MFA 动态验证码' }]
                    : []),
                  { pattern: /^\d{6,8}$/, message: '请输入 6 至 8 位数字验证码' },
                ]}
              >
                <Input
                  prefix={<SafetyCertificateOutlined />}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={8}
                  required={emergency}
                />
              </Form.Item>
              <Button type="primary" htmlType="submit" block loading={authenticating}>
                {emergency ? '进入应急会话' : '登录'}
              </Button>
            </Form>
          ) : null}

          {!emergency && (loginMode === 'sso' || loginMode === 'fault') ? (
            <Button block onClick={() => setEmergency(true)}>
              应急管理员登录
            </Button>
          ) : null}
          {emergency && localAllowed ? (
            <Button type="link" onClick={() => setEmergency(false)}>
              返回普通本地登录
            </Button>
          ) : null}
          {loginMode === null ? (
            <Button onClick={() => void reloadLoginState()}>重新加载登录配置</Button>
          ) : null}
        </Space>
      </Card>
    </main>
  );
}

function loginHeading(mode: LoginMode | null): string {
  if (mode === 'sso') return '企业 SSO 已启用';
  if (mode === 'fault') return 'SSO 服务异常';
  return '登录管理控制台';
}

function loginDescription(mode: LoginMode | null): string {
  if (mode === 'sso') return '普通本地账户已停用，企业身份认证保持唯一常规入口。';
  if (mode === 'fault') return '身份平台当前不可用，仅受控应急管理员可继续。';
  return '使用平台本地账户继续。管理员账户需要满足 MFA 策略。';
}
