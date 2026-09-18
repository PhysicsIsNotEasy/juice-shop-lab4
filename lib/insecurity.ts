/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from '@juice-shop/models/user'
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

const readPem = (value?: string) => value?.replace(/\\r\\n/g, '\r\n').replace(/\\n/g, '\n')
export const publicKey = readPem(process.env.JWT_PUBLIC_KEY) ?? fs.readFileSync(process.env.JWT_PUBLIC_KEY_FILE ?? 'encryptionkeys/jwt.pub', 'utf8')
const privateKey = readPem(process.env.JWT_PRIVATE_KEY) ?? fs.readFileSync(process.env.JWT_PRIVATE_KEY_FILE ?? 'encryptionkeys/jwt.key', 'utf8')
const hmacKey = process.env.HMAC_KEY ?? fs.readFileSync(process.env.HMAC_KEY_FILE ?? 'encryptionkeys/hmac.key', 'utf8').trim()
const deluxeTokenKey = crypto.createSecretKey(crypto.createHash('sha256').update(privateKey).digest('hex'))

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', hmacKey).update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (str.includes(nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const isAuthorized = () => expressjwt(({ secret: publicKey, algorithms: ['RS256'] }))
export const denyAll = () => expressjwt({ secret: '' + Math.random(), algorithms: ['RS256'] })
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
export const verify = (token: string) => {
  if (!token) return false

  try {
    return (jws.verify as (token: string, algorithm: string, secret: string) => boolean)(token, 'RS256', publicKey)
  } catch {
    return false
  }
}
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)

export function evaluateSafeArithmeticExpression (expression: string): number {
  const sanitized = expression.replace(/\s+/g, '')
  if (!/^(?:\d+\.?\d*|\.\d+|[()+\-*/])+$/i.test(sanitized)) {
    throw new Error('Unsupported expression')
  }

  const values: number[] = []
  const operators: string[] = []
  const precedence: Record<string, number> = { '+': 1, '-': 1, '*': 2, '/': 2 }

  const applyOperator = (operator: string) => {
    const right = values.pop()
    const left = values.pop()

    if (left === undefined || right === undefined) {
      throw new Error('Invalid expression')
    }

    switch (operator) {
      case '+':
        values.push(left + right)
        break
      case '-':
        values.push(left - right)
        break
      case '*':
        values.push(left * right)
        break
      case '/':
        if (right === 0) {
          throw new Error('Division by zero')
        }
        values.push(left / right)
        break
      default:
        throw new Error('Unsupported operator')
    }
  }

  const tokens = sanitized.match(/\d+\.?\d*|\.\d+|[()+\-*/]/g) ?? []
  if (tokens.length === 0) {
    throw new Error('Empty expression')
  }

  for (const token of tokens) {
    if (/^\d+(?:\.\d+)?$|^\.\d+$/.test(token)) {
      values.push(Number(token))
      continue
    }

    if (token === '(') {
      operators.push(token)
      continue
    }

    if (token === ')') {
      while (operators.length && operators[operators.length - 1] !== '(') {
        applyOperator(operators.pop() as string)
      }
      if (operators.pop() !== '(') {
        throw new Error('Mismatched parentheses')
      }
      continue
    }

    while (
      operators.length &&
      operators[operators.length - 1] !== '(' &&
      precedence[operators[operators.length - 1] as string] >= precedence[token]
    ) {
      applyOperator(operators.pop() as string)
    }
    operators.push(token)
  }

  while (operators.length) {
    const operator = operators.pop()
    if (operator === '(') {
      throw new Error('Mismatched parentheses')
    }
    applyOperator(operator as string)
  }

  if (values.length !== 1) {
    throw new Error('Malformed expression')
  }

  return values[0]
}

export const getSafeFilePath = (file: string, baseDir = '.') => {
  if (typeof file !== 'string' || file.length === 0) {
    throw new Error('Invalid file name!')
  }

  if (file.includes('/') || file.includes('\\') || file.includes('..') || path.isAbsolute(file)) {
    throw new Error('File names cannot contain path separators or traversal sequences!')
  }

  const safeFile = path.basename(file)
  if (safeFile !== file || !/^[A-Za-z0-9._-]+$/.test(safeFile)) {
    throw new Error('Invalid file name!')
  }

  const resolvedBaseDir = path.resolve(baseDir)
  const resolvedFilePath = path.resolve(resolvedBaseDir, safeFile)
  const relativePath = path.relative(resolvedBaseDir, resolvedFilePath)

  if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    throw new Error('File must stay inside the configured root directory!')
  }

  if (fs.existsSync(resolvedBaseDir)) {
    const realBaseDir = fs.realpathSync(resolvedBaseDir)
    const realFilePath = fs.existsSync(resolvedFilePath) ? fs.realpathSync(resolvedFilePath) : resolvedFilePath
    const realRelativePath = path.relative(realBaseDir, realFilePath)

    if (realRelativePath.startsWith('..') || path.isAbsolute(realRelativePath)) {
      throw new Error('File escapes the configured root directory!')
    }
  }

  return resolvedFilePath
}

export const sendSafeFile = (res: Response, file: string, baseDir = '.') => {
  const safeFilePath = getSafeFilePath(file, baseDir)
  return res.sendFile(safeFilePath)
}

export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export function getAllowedRedirect (value: string | undefined): string | null {
  if (!value || typeof value !== 'string') return null

  try {
    const parsed = new URL(value)
    if (!['http:', 'https:'].includes(parsed.protocol)) return null

    const normalized = `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}`
    for (const allowedUrl of redirectAllowlist) {
      const allowed = new URL(allowedUrl)
      const sameOrigin = parsed.protocol === allowed.protocol && parsed.host === allowed.host
      const allowedPath = allowed.pathname.replace(/\/$/, '')
      const allowedPathPrefix = parsed.pathname === allowedPath || parsed.pathname.startsWith(`${allowedPath}/`)

      if (sameOrigin && allowedPathPrefix) return normalized
    }

    return null
  } catch {
    return null
  }
}

// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', deluxeTokenKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isAdmin = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.admin) {
      next()
    } else {
      res.status(403).json({ error: 'Admin access required' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token && authenticatedUsers.get(token) === undefined) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null && decoded?.data !== undefined) {
        authenticatedUsers.put(token, decoded)
        res.cookie('token', token)
      }
    })
  }
  next()
}
