import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const path = process.argv[2] || 'frontend-admin/src/views/QueryView.vue'
const source = readFileSync(path, 'utf8')
const functions = source.slice(source.indexOf('function resolveFilename('), source.indexOf('const queryAccessParams ='))

async function scenario(action, expected, { fail, noHeader = false, enabled = true } = {}) {
  const requests = [], saved = [], errors = [], messages = []
  const params = { job_id: 'query-job', token: 'query-token' }
  const reauthParams = { token: 'reauth-token' }
  const request = async (kind, access) => {
    requests.push({ kind, access })
    if (kind === fail) throw { response: { data: new Blob([JSON.stringify({ error: 'download failed' })]) } }
    return { data: new Blob([kind]), headers: noHeader ? {} : { 'content-disposition': `attachment; filename="${kind}.download"` } }
  }
  const ctx = vm.createContext({
    Blob,
    downloadState: { value: {} },
    queryAccessParams: { value: params },
    reauthAccessParams: { value: reauthParams },
    canDownload: { value: enabled }, reauthDone: { value: enabled },
    reauth: { value: { job: { id: 'reauth-job' } } },
    downloadQueryFiles: (access) => request('cpa', access),
    downloadQuerySub: (access) => request('sub', access),
    downloadQueryTwoFactor: (access) => request('2fa', access),
    downloadQueryReauth: (job, format, access) => {
      assert.equal(job, 'reauth-job')
      return request(format, access)
    },
    ElMessage: { success: (msg) => messages.push(msg) },
    showRequestError: (err) => errors.push(err),
    setTimeout: () => {},
    recordSave: (blob, filename) => saved.push({ blob, filename }),
  })
  vm.runInContext(functions + '\nsaveBlobFile = recordSave', ctx)
  await vm.runInContext(action, ctx)
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(requests.map(r => r.kind), expected, `${action}: wrong downloads`)
  for (const req of requests) {
    assert.equal(req.access, action.startsWith('downloadReauth') ? reauthParams : params)
  }
  if (fail) {
    assert.equal(saved.length, 0, 'must prepare both files before saving either')
    assert.equal(messages.length, 0)
    assert.equal(errors.length, 1)
    assert.equal(errors[0].response.data.error, 'download failed')
  } else {
    assert.equal(saved.length, expected.length)
    assert.equal(errors.length, 0)
    assert.deepEqual(await Promise.all(saved.map(s => s.blob.text())), expected)
    assert(saved.every(s => typeof s.filename === 'string'), 'download name must be a string')
    if (!noHeader) assert.deepEqual(saved.map(s => s.filename), expected.map(k => k + '.download'))
  }
  return saved.map(s => s.filename)
}

try {
  await scenario('downloadZip()', ['cpa', '2fa'])
  await scenario('downloadSub()', ['sub', '2fa'])
  await scenario('downloadTwoFactor()', ['2fa'])
  for (const format of ['cpa', 'sub2api', 'card-cpa', 'card-sub2api']) {
    await scenario(`downloadReauth('${format}')`, [format, format.startsWith('card-') ? 'card-2fa' : '2fa'])
  }
  for (const format of ['2fa', 'card-2fa']) await scenario(`downloadReauth('${format}')`, [format])
  assert.deepEqual(await scenario('downloadZip()', ['cpa', '2fa'], { noHeader: true }), ['query-files.zip', 'accounts-2fa.txt'])
  await scenario('downloadZip()', ['cpa', '2fa'], { fail: 'cpa' })
  await scenario('downloadSub()', ['sub', '2fa'], { fail: '2fa' })
  await scenario('downloadZip()', [], { enabled: false })
  await scenario("downloadReauth('cpa')", [], { enabled: false })
  console.log('PASS: CPA/Sub paired 2FA; reauth scope; standalone TXT; filenames; access params; failure handling; unfinished job guards')
} catch (error) {
  console.error('FAIL: ' + error.message)
  process.exitCode = 1
}
