import { ArrowLeftOutlined, CheckCircleOutlined } from '@ant-design/icons';
import {
  PageContainer,
  ProCard,
  ProForm,
  ProFormSelect,
  ProFormText,
  ProFormTextArea,
} from '@ant-design/pro-components';
import { Alert, Button, Result, Space } from 'antd';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiProblemError, apiClient, type CreateProductInput } from '../../api/client';

export function ProductCreatePage() {
  const navigate = useNavigate();
  const [problem, setProblem] = useState<ApiProblemError | null>(null);
  const [created, setCreated] = useState(false);

  if (created) {
    return (
      <PageContainer title="创建产品">
        <Result
          status="success"
          title="产品已创建并通过 Manifest 校验"
          subTitle="默认通道与产品范围已经建立，可以继续上传制品。"
          extra={
            <Button type="primary" onClick={() => navigate('/products')}>
              返回产品列表
            </Button>
          }
        />
      </PageContainer>
    );
  }

  return (
    <PageContainer
      title="创建产品"
      content="产品 Manifest 使用 xminds-product-manifest/v1 契约，创建后保持不可变。"
      extra={
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/products')}>
          返回
        </Button>
      }
    >
      <ProCard className="page-card" style={{ maxWidth: 860 }}>
        {problem ? (
          <Alert
            type="error"
            showIcon
            closable
            onClose={() => setProblem(null)}
            title={`${problem.problem.title}${problem.problem.code ? `（${problem.problem.code}）` : ''}`}
            description={
              <Space orientation="vertical" size={2}>
                <span>{problem.problem.detail || '请检查产品清单后重试。'}</span>
                {problem.problem.request_id ? (
                  <strong className="mono">请求 ID：{problem.problem.request_id}</strong>
                ) : null}
              </Space>
            }
            style={{ marginBottom: 24 }}
          />
        ) : null}
        <ProForm<CreateProductInput>
          layout="vertical"
          initialValues={{
            id: 'new-product',
            name: '新产品',
            description: '企业软件可信发布产品',
            default_channel: 'stable',
          }}
          submitter={{
            searchConfig: { submitText: '创建产品', resetText: '重置' },
            submitButtonProps: { icon: <CheckCircleOutlined />, 'aria-label': '创建产品' },
          }}
          onFinish={async (values) => {
            setProblem(null);
            try {
              await apiClient.createProduct(values);
              setCreated(true);
              return true;
            } catch (error) {
              if (error instanceof ApiProblemError) {
                setProblem(error);
              } else {
                setProblem(
                  new ApiProblemError({
                    type: 'about:blank',
                    title: '网络请求失败',
                    status: 0,
                    detail: '无法连接管理 API，请检查网络或稍后重试。',
                  }),
                );
              }
              return false;
            }
          }}
        >
          <ProFormText
            name="id"
            label="产品标识"
            tooltip="创建后不可修改，建议使用小写字母、数字和连字符。"
            rules={[
              { required: true, message: '请输入产品标识' },
              { pattern: /^[a-z0-9]+(?:-[a-z0-9]+)*$/, message: '仅允许小写字母、数字和连字符' },
            ]}
          />
          <ProFormText
            name="name"
            label="产品名称"
            rules={[{ required: true, message: '请输入产品名称' }]}
          />
          <ProFormTextArea name="description" label="产品说明" fieldProps={{ rows: 3 }} />
          <ProFormSelect
            name="default_channel"
            label="默认通道"
            options={[
              { label: 'stable', value: 'stable' },
              { label: 'preview', value: 'preview' },
              { label: 'beta', value: 'beta' },
            ]}
            rules={[{ required: true }]}
          />
        </ProForm>
      </ProCard>
    </PageContainer>
  );
}
