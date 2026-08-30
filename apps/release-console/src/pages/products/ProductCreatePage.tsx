import { ArrowLeftOutlined, CheckCircleOutlined } from '@ant-design/icons';
import {
  PageContainer,
  ProCard,
  ProForm,
  ProFormList,
  ProFormSelect,
  ProFormText,
} from '@ant-design/pro-components';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Result, Space, Tag, Typography } from 'antd';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiContractError, ApiProblemError, apiClient } from '../../api/client';
import type { Product, ProductChannelManifest, ProductManifestV1 } from '../../api/types';

interface ProductCreateFormValues {
  product_id: string;
  display_name: string;
  artifact_types: string[];
  compatibility_keys: string[];
  default_channels: ProductChannelManifest[];
}

const identifierPattern = /^[a-z][a-z0-9._-]{0,63}$/;

function buildProductManifest(values: ProductCreateFormValues): ProductManifestV1 {
  return {
    schema_version: 'xminds-product-manifest/v1',
    product_id: values.product_id,
    display_name: values.display_name,
    artifact_types: values.artifact_types,
    version_scheme: 'semver',
    compatibility_keys: values.compatibility_keys ?? [],
    catalog_format: 'xminds-tuf-v1',
    default_channels: values.default_channels,
  };
}

function displayProblem(error: unknown): ApiProblemError {
  if (error instanceof ApiProblemError) {
    return error;
  }
  if (error instanceof ApiContractError) {
    return new ApiProblemError({
      type: 'about:blank',
      title: 'API 响应不符合契约',
      status: 0,
      detail: error.message,
    });
  }
  return new ApiProblemError({
    type: 'about:blank',
    title: '网络请求失败',
    status: 0,
    detail: '无法连接管理 API，请检查网络或稍后重试。',
  });
}

export function ProductCreatePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [problem, setProblem] = useState<ApiProblemError | null>(null);
  const [created, setCreated] = useState<Product | null>(null);
  const createProduct = useMutation({
    mutationFn: (manifest: ProductManifestV1) => apiClient.createProduct(manifest),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['products'] });
    },
  });

  if (created) {
    return (
      <PageContainer title="创建产品">
        <Result
          status="success"
          title="产品已创建并通过 Manifest 校验"
          subTitle={`${created.displayName}（${created.id}）的默认通道与发布范围已建立，可以继续上传制品。`}
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
        <ProForm<ProductCreateFormValues>
          layout="vertical"
          initialValues={{
            product_id: 'new-product',
            display_name: '新产品',
            artifact_types: ['generic-binary'],
            compatibility_keys: [],
            default_channels: [{ name: 'stable', display_name: 'Stable' }],
          }}
          submitter={{
            searchConfig: { submitText: '创建产品', resetText: '重置' },
            submitButtonProps: {
              icon: <CheckCircleOutlined />,
              'aria-label': '创建产品',
              loading: createProduct.isPending,
            },
          }}
          onFinish={async (values) => {
            setProblem(null);
            try {
              const product = await createProduct.mutateAsync(buildProductManifest(values));
              setCreated(product);
              return true;
            } catch (error) {
              setProblem(displayProblem(error));
              return false;
            }
          }}
        >
          <Alert
            type="info"
            showIcon
            title="Manifest 固定契约"
            description={
              <Space size={[6, 6]} wrap>
                <Typography.Text type="secondary">Schema</Typography.Text>
                <Tag>xminds-product-manifest/v1</Tag>
                <Typography.Text type="secondary">版本规则</Typography.Text>
                <Tag>semver</Tag>
                <Typography.Text type="secondary">目录格式</Typography.Text>
                <Tag>xminds-tuf-v1</Tag>
              </Space>
            }
            style={{ marginBottom: 24 }}
          />
          <ProFormText
            name="product_id"
            label="产品标识"
            tooltip="创建后不可修改，建议使用小写字母、数字和连字符。"
            rules={[
              { required: true, message: '请输入产品标识' },
              {
                pattern: /^[a-z][a-z0-9-]{1,62}$/,
                message: '必须以小写字母开头，长度 2–63，仅允许小写字母、数字和连字符',
              },
            ]}
          />
          <ProFormText
            name="display_name"
            label="产品名称"
            fieldProps={{ maxLength: 128, showCount: true }}
            rules={[
              { required: true, whitespace: true, message: '请输入产品名称' },
              { pattern: /^\S(?:.*\S)?$/, message: '名称首尾不得包含空白字符' },
            ]}
          />
          <ProFormSelect
            name="artifact_types"
            label="制品类型"
            tooltip="可选择建议值或直接输入合法标识。"
            options={[
              { label: 'generic-binary', value: 'generic-binary' },
              { label: 'macos-dmg', value: 'macos-dmg' },
              { label: 'windows-msi', value: 'windows-msi' },
              { label: 'linux-deb', value: 'linux-deb' },
              { label: 'oci-image', value: 'oci-image' },
            ]}
            fieldProps={{ mode: 'tags', tokenSeparators: [',', '、', ' '] }}
            rules={[
              { required: true, type: 'array', min: 1, message: '至少需要一种制品类型' },
              {
                validator: async (_, values: string[] | undefined) => {
                  if ((values ?? []).some((value) => !identifierPattern.test(value))) {
                    throw new Error(
                      '制品类型必须以小写字母开头，且仅包含小写字母、数字、点、下划线或连字符',
                    );
                  }
                  if (new Set(values ?? []).size !== (values ?? []).length) {
                    throw new Error('制品类型不得重复');
                  }
                },
              },
            ]}
          />
          <ProFormSelect
            name="compatibility_keys"
            label="兼容性键"
            tooltip="用于目录筛选与客户端兼容性判定，可为空。"
            options={[
              { label: 'platform', value: 'platform' },
              { label: 'architecture', value: 'architecture' },
              { label: 'edition', value: 'edition' },
              { label: 'deployment-mode', value: 'deployment-mode' },
            ]}
            fieldProps={{ mode: 'tags', tokenSeparators: [',', '、', ' '] }}
            rules={[
              {
                validator: async (_, values: string[] | undefined) => {
                  if ((values ?? []).some((value) => !identifierPattern.test(value))) {
                    throw new Error('兼容性键格式不符合 Manifest 契约');
                  }
                  if (new Set(values ?? []).size !== (values ?? []).length) {
                    throw new Error('兼容性键不得重复');
                  }
                },
              },
            ]}
          />
          <ProFormList<ProductChannelManifest>
            name="default_channels"
            label="默认通道"
            tooltip="列表顺序即通道优先级，第一项为主默认通道。"
            min={1}
            max={16}
            required
            isValidateList
            emptyListMessage="至少需要一个默认通道"
            creatorRecord={{ name: 'preview', display_name: 'Preview' }}
            creatorButtonProps={{ creatorButtonText: '添加默认通道' }}
            copyIconProps={false}
            arrowSort
          >
            <ProForm.Group>
              <ProFormText
                name="name"
                label="通道标识"
                width="md"
                rules={[
                  { required: true, message: '请输入通道标识' },
                  { pattern: identifierPattern, message: '通道标识格式不符合 Manifest 契约' },
                ]}
              />
              <ProFormText
                name="display_name"
                label="显示名称"
                width="md"
                fieldProps={{ maxLength: 128 }}
                rules={[
                  { required: true, whitespace: true, message: '请输入通道显示名称' },
                  { pattern: /^\S(?:.*\S)?$/, message: '显示名称首尾不得包含空白字符' },
                ]}
              />
            </ProForm.Group>
          </ProFormList>
        </ProForm>
      </ProCard>
    </PageContainer>
  );
}
