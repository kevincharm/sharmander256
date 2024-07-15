import { expect } from 'chai'
import { sha256 } from '../src/sha256'
import sha256ShortMsgTestVectors from './nist/sha256ShortMsg'
import sha256LongMsgTestVectors from './nist/sha256LongMsg'

describe('sha256', () => {
    describe('NIST SHA-256 short message tests', () => {
        for (const { msg, digest } of sha256ShortMsgTestVectors) {
            it(`L=${msg.length / 2}`, () => {
                const m = Buffer.from(msg, 'hex')
                expect(sha256(m)).to.deep.eq(Buffer.from(digest, 'hex'))
            })
        }
    })

    describe('NIST SHA-256 long message tests', () => {
        for (const { msg, digest } of sha256LongMsgTestVectors) {
            it(`L=${msg.length / 2}`, () => {
                const m = Buffer.from(msg, 'hex')
                expect(sha256(m)).to.deep.eq(Buffer.from(digest, 'hex'))
            })
        }
    })
})
