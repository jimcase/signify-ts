// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { SignifyClient, ready, Serder, Diger, MtrDex } from "signify-ts";
import {strict as assert} from "assert";
import { useState, useEffect } from 'react';


export function Multisig() {
    const [testResult, setTestResult] = useState('');
    useEffect(() => {
        ready().then(() => {
            console.log("signify client is ready")
        })
    }, [])

    return (
        <>
            <div className="card">
                <button
                    onClick={async () => {
                        try {
                            const url = "http://localhost:3901"
                            const bran = '0123456789abcdefghijk'
                            const client = new SignifyClient(url, bran)
                            assert.equal(client.controller.pre, 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose')
                            const r1 = await client.boot()
                            assert.equal(r1.status, 202)
                            await client.connect()
                            assert.notEqual(client.agent, undefined)
                            assert.equal(client.agent?.pre, 'EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei')
                            assert.equal(client.agent?.anchor, 'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose')
                                                        
                            
                            const identifiers = client.identifiers()
                            const operations = client.operations()
                            const oobis = client.oobis()

                            const icp = await identifiers.create('aid1', {bran: '0123456789abcdefghijk' })
                            const serder = new Serder(icp)
                            assert.equal(serder.pre, "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK")
                            
                            await identifiers.addEndRole("aid1", 'agent', client.agent.pre)

                            let oobi = await oobis.get("aid1")
                            console.log(oobi)

                            let op = await oobis.resolve("http://127.0.0.1:5642/oobi/EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha","multisig1")
                            while (!op["done"]) {
                                op = await operations.get(op["name"]);
                                await new Promise(resolve => setTimeout(resolve, 1000)); // sleep for 1 second
                            }
                            const multisig1 = op["response"]

                            op = await oobis.resolve("http://127.0.0.1:5642/oobi/EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha","multisig2")
                            while (!op["done"]) {
                                op = await operations.get(op["name"]);
                                await new Promise(resolve => setTimeout(resolve, 1000)); // sleep for 1 second
                            }
                            const multisig2 = op["response"]

                            

                            // let aids = await identifiers.list_identifiers()
                            // assert.equal(aids.length, 0)

                            // let aid = await identifiers.create('aid1', {algo: 'randy'})
                            // const icp = await new Serder(aid)
                            // assert.equal(icp.verfers.length, 1)
                            // assert.equal(icp.digers.length, 1)
                            // assert.equal(icp.ked['kt'], '1')
                            // assert.equal(icp.ked['nt'], '1')


                            // aids = await identifiers.list_identifiers()
                            // assert.equal(aids.length, 1)
                            // aid = aids[0]
                            // assert.equal(aid.name, 'aid1')
                            // assert.equal(aid.prefix, icp.pre)

                            // let ked = await identifiers.interact("aid1", [icp.pre])
                            // let ixn = await new Serder(ked)
                            // assert.equal(ixn.ked['s'], '1')
                            // assert.deepEqual(ixn.ked['a'], [icp.pre])

                            // aids = await identifiers.list_identifiers()
                            // assert.equal(aids.length, 1)
                            // aid = aids[0]

                            // const events = client.key_events()
                            // let log = await events.get(aid["prefix"])
                            // assert.equal(log.length, 2)

                            // ked = await identifiers.rotate('aid1',{})
                            // let rot = await new Serder(ked)
                            // assert.equal(rot.ked['s'], '2')
                            // assert.equal(rot.verfers.length, 1)
                            // assert.equal(rot.digers.length, 1)
                            // assert.notEqual(rot.verfers[0].qb64, icp.verfers[0].qb64)
                            // assert.notEqual(rot.digers[0].qb64, icp.digers[0].qb64)
                            // let dig = new Diger({code: MtrDex.Blake3_256},rot.verfers[0].qb64b, )
                            // assert.equal(dig.qb64, icp.digers[0].qb64)
                            // log = await events.get(aid["prefix"])
                            // assert.equal(log.length, 3)
                            
                            setTestResult("Passed")
                        }
                        catch (e) {
                            console.log(e)
                            setTestResult("Failed")
                        }
                    }} >Multisig Integration Test</button>{testResult}
            </div>
        </>
    )
}


