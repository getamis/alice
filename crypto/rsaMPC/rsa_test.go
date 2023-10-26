// Copyright © 2020 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package mpcrsa

import (
	"fmt"
	"math/big"
	mathRandom "math/rand"
	"testing"

	. "github.com/onsi/ginkgo"

	//. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Util test", func() {
	It("zero rank", func() {
		var p, q, N *big.Int
		numberOfPrime := 80
		n := 4
		// Chinese Recover (Now use extend)
		bjxj, product := chineseRecover(numberOfPrime)
		partyList := make([]*BiPrimeManage, n)

		// Initial all parties
		for i := 0; i < n; i++ {
			partyList[i], _ = NewBFSampling(n, numberOfPrime, i == 0)
		}

		for j := 0; j < 10000; j++ {
			for i := 0; i < 4000; i++ {
				for l := 0; l < numberOfPrime; l++ {
					pi := partyList[0].pij[l]
					qi := partyList[0].qij[l]

					for z := 1; z < n; z++ {
						pi += partyList[z].pij[l]
						qi += partyList[z].qij[l]
					}

					Ni := (pi * qi) % primeList[l]
					if Ni != 0 {
						for z := 0; z < n; z++ {
							partyList[z].Nj[l] = Ni
						}

					} else {
						for z := 0; z < 1000; z++ {
							// Refresh divide part
							Refreshpij := make([]int64, n)
							Refreshqij := make([]int64, n)

							pi = 0
							qi = 0
							for z := 0; z < n; z++ {
								Refreshpij[z] = mathRandom.Int63n(primeList[l])
								Refreshqij[z] = mathRandom.Int63n(primeList[l])
								pi += Refreshpij[z]
								qi += Refreshqij[z]
							}
							Ni = (pi * qi) % primeList[l]
							if Ni != 0 {
								// Set New state
								for z := 0; z < n; z++ {
									partyList[z].Nj[l] = Ni
									partyList[z].pij[l] = Refreshpij[z]
									partyList[z].qij[l] = Refreshqij[z]
								}
								break
							}
						}
					}
				}
				partyPi := make([]*big.Int, n)
				partyQi := make([]*big.Int, n)

				for z := 0; z < n; z++ {
					partyPi[z] = big.NewInt(0)
					partyQi[z] = big.NewInt(0)
					for l := 0; l < numberOfPrime; l++ {
						pi := big.NewInt(partyList[z].pij[l])
						temp := new(big.Int).Mul(bjxj[l], pi)
						partyPi[z].Add(partyPi[z], temp)
						partyPi[z].Mod(partyPi[z], product)

						qi := big.NewInt(partyList[z].qij[l])
						temp = new(big.Int).Mul(bjxj[l], qi)
						partyQi[z].Add(partyQi[z], temp)
						partyQi[z].Mod(partyQi[z], product)
					}
				}

				p = big.NewInt(0)
				q = big.NewInt(0)
				for z := 0; z < n; z++ {
					p.Add(p, partyPi[z])
					q.Add(q, partyQi[z])
				}
				N = new(big.Int).Mul(p, q)

				if !checkDivisible(N, numberOfPrime) {
					for z := 0; z < n; z++ {
						partyList[z].N = new(big.Int).Set(N)
						partyList[z].pi = partyPi[z]
						partyList[z].qi = partyQi[z]
					}
					break
				} else {
					// Reset
					for i := 0; i < n; i++ {
						partyList[i], _ = NewBFSampling(n, numberOfPrime, i == 0)
					}
				}
			}

			epsilonP := big.NewInt(1)
			epsilonQ := big.NewInt(1)
			if new(big.Int).Mod(p, big4).Cmp(big1) == 0 {
				epsilonP.Neg(epsilonP)
			}
			if new(big.Int).Mod(q, big4).Cmp(big1) == 0 {
				epsilonQ.Neg(epsilonQ)
			}
			epsilonN := new(big.Int).Mul(epsilonP, epsilonQ)

			for z := 0; z < n; z++ {
				partyList[z].epsilonP = epsilonP
				partyList[z].epsilonQ = epsilonQ
				partyList[z].epsilonN = epsilonN
			}

			//
			count := 0
			leakCount := 0
			bigLowerLength := 20
			uList := make([]*big.Int, n)
			vList := make([]*big.Int, n)
			for k := 0; k < 80; k++ {
				P, D, temp, err := generateRamdonDandP(bigLowerLength, int(epsilonP.Int64()), p, N)

				for z := 0; z < n; z++ {
					u, v := partyList[z].computeLucasMatrice(D, P)
					uList[z] = u
					vList[z] = v
				}

				for z := 0; z < n; z++ {
					err = partyList[z].CheckLucasCongruence(uList, vList, D)
					if err != nil {
						break
					}
				}
				if err != nil {
					fmt.Println("Failure:", j)
					break
				} else {
					fmt.Println("MaybeOK", k)
					leakCount += temp
					count++
					continue
				}
			}
			if count > 79 {
				fmt.Println("P:", p)
				fmt.Println("Q:", q)
				fmt.Println("leakCount:", leakCount)
				fmt.Println("Prime")
				break
			} else {
				// Reset
				for i := 0; i < n; i++ {
					partyList[i], _ = NewBFSampling(n, numberOfPrime, i == 0)
				}
			}
		}

	})

	// FIt("Exp", func() {
	// 	D, _ := new(big.Int).SetString("20", 10)
	// 	N := big.NewInt(23)
	// 	//exp1 := big.NewInt(76)
	// 	exp2 := big.NewInt(-3)
	// 	exp3 := big.NewInt(3)
	// 	//u, v := specialExp(P, D, N, exp1)

	// 	u2, v2 := specialExp(big.NewInt(2), big.NewInt(5), D, N, exp2)
	// 	u3, v3 := specialExp(big.NewInt(2), big.NewInt(5), D, N, exp3)
	// 	fmt.Println(specialInverse(u2, v2, D, N))
	// 	fmt.Println(u2, v2)
	// 	fmt.Println(u3, v3)
	// 	// fmt.Println(u3,v3)
	// 	fmt.Println(specialMul(u3, v3, u2, v2, D, N))
	// })
})

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "MpcRsa Test")
}
