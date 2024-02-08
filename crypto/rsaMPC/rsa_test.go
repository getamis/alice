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
	"crypto/rand"
	"fmt"
	"math/big"
	mathRandom "math/rand"
	"testing"
	"time"

	"github.com/getamis/alice/crypto/utils"
	. "github.com/onsi/ginkgo"

	//. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Util test", func() {
	It("Lucas Biprimality test", func() {
		// 30, 56, 1
		// 2048: 131, 235, 17; 3072: 183, 329, 25
		var p, q, N *big.Int
		numberOfPrime := 131
		numberOfExtendPrime := 235
		divisibleIndex := 17
		n := 2
		// Chinese Recover (Compute p and q)
		bjxj, product := chineseRecover(numberOfPrime)
		partyList := make([]*BiPrimeManage, n)
		tryTime := 5

		// Chinese Recover (Now use extend)
		bjxjExtend, exptendProduct := chineseRecover(numberOfExtendPrime)
		diffNumberPrime := numberOfExtendPrime - numberOfPrime
		timeList := make([]string, tryTime)
		leakCountList := make([]int, tryTime)
		LagrangeCoefficient := make([]*big.Int, (2*n)-1)
		LagrangeCoefficientInt64 := make([]int64, (2*n)-1)
		maxTry := 20000

		for i := 0; i < len(LagrangeCoefficient); i++ {
			bigI := big.NewInt(int64(i + 1))
			tempUp := big.NewInt(1)
			tempLower := big.NewInt(1)
			for j := 0; j < len(LagrangeCoefficient); j++ {
				if j != i {
					bigJ := big.NewInt(int64(j) + 1)
					temp := new(big.Int).Neg(bigJ)
					tempUp.Mul(tempUp, temp)
					tempLower.Mul(tempLower, new(big.Int).Sub(bigI, bigJ))
				}
			}
			LagrangeCoefficient[i] = new(big.Int).Div(tempUp, tempLower)
			LagrangeCoefficientInt64[i] = LagrangeCoefficient[i].Int64()
		}

		for m := 0; m < tryTime; m++ {
			start := time.Now()
			// Initial all parties
			for z := 0; z < n; z++ {
				partyList[z], _ = NewBFSampling(n, numberOfPrime, z == 0)
			}
			for j := 0; j < maxTry; j++ {
				for i := 0; i < 4000; i++ {
					for l := 1; l < numberOfPrime; l++ {
						piList := make([]int64, n)
						qiList := make([]int64, n)
						rList := make([]int64, n)
						for z := 0; z < n; z++ {
							piList[z] = partyList[z].pij[l]
							qiList[z] = partyList[z].qij[l]
							rList[z] = mathRandom.Int63n(primeList[l])
						}
						piqiList := MPCMulShamirInt64(piList, qiList, LagrangeCoefficientInt64, primeList[l])
						NiGCD := MPCGCDInt64(rList, piqiList, LagrangeCoefficientInt64, primeList[l])
						Ni := int64(0)
						if NiGCD == 1 {
							for z := 0; z < n; z++ {
								Ni += piqiList[z]
							}
							Ni = Ni % primeList[l]
						}
						if Ni != 0 {
							for z := 0; z < n; z++ {
								partyList[z].Nj[l] = Ni
							}
						} else {
							for try := 0; try < 1000; try++ {
								// Refresh divide part
								Refreshpij := make([]int64, n)
								Refreshqij := make([]int64, n)
								for z := 0; z < n; z++ {
									Refreshpij[z] = mathRandom.Int63n(primeList[l])
									Refreshqij[z] = mathRandom.Int63n(primeList[l])
									rList[z] = mathRandom.Int63n(primeList[l])
								}
								piqiList := MPCMulShamirInt64(Refreshpij, Refreshqij, LagrangeCoefficientInt64, primeList[l])
								NiGCD := MPCGCDInt64(rList, piqiList, LagrangeCoefficientInt64, primeList[l])
								Ni := int64(0)
								if NiGCD == 1 {
									for z := 0; z < n; z++ {
										Ni += piqiList[z]
									}
									Ni = Ni % primeList[l]
								}
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
					pMod4List := make([]int64, n)
					qMod4List := make([]int64, n)

					// CRT
					p = big.NewInt(0)
					q = big.NewInt(0)
					for z := 0; z < n; z++ {
						tempPi := big.NewInt(0)
						tempQi := big.NewInt(0)
						for l := 0; l < numberOfPrime; l++ {
							pi := big.NewInt(partyList[z].pij[l])
							temp := new(big.Int).Mul(bjxj[l], pi)
							tempPi.Add(tempPi, temp)
							tempPi.Mod(tempPi, product)

							qi := big.NewInt(partyList[z].qij[l])
							temp = new(big.Int).Mul(bjxj[l], qi)
							tempQi.Add(tempQi, temp)
							tempQi.Mod(tempQi, product)
						}
						pMod4List[z] = new(big.Int).Mod(tempPi, big4).Int64()
						qMod4List[z] = new(big.Int).Mod(tempQi, big4).Int64()

						partyList[z].pi = tempPi
						partyList[z].qi = tempQi
						// just Use in Modify
						p.Add(p, tempPi)
						q.Add(q, tempQi)
					}

					// MPC CRT extend
					for z := 0; z < n; z++ {
						tempExpendP := make([]int64, diffNumberPrime)
						tempExpendQ := make([]int64, diffNumberPrime)
						for w := numberOfPrime; w < numberOfExtendPrime; w++ {
							startIndex := w - numberOfPrime
							prime := big.NewInt(primeList[w])
							tempExpendP[startIndex] = (new(big.Int).Mod(partyList[z].pi, prime)).Int64()

							tempExpendQ[startIndex] = (new(big.Int).Mod(partyList[z].qi, prime)).Int64()
						}
						partyList[z].pij = append(partyList[z].pij, tempExpendP...)
						partyList[z].qij = append(partyList[z].qij, tempExpendQ...)
					}

					// Locally product
					NijList := make([]*big.Int, numberOfExtendPrime)
					for w := 0; w < numberOfExtendPrime; w++ {
						pijList := make([]*big.Int, n)
						qijList := make([]*big.Int, n)
						for z := 0; z < n; z++ {
							pijList[z] = big.NewInt(partyList[z].pij[w])
							qijList[z] = big.NewInt(partyList[z].qij[w])
						}
						prime := big.NewInt(primeList[w])
						partyLocalProductShare := MPCMulShamir(pijList, qijList, LagrangeCoefficient, prime)

						Nij := big.NewInt(0)
						for z := 0; z < n; z++ {
							Nij.Add(partyLocalProductShare[z], Nij)
						}
						Nij.Mod(Nij, prime)
						NijList[w] = Nij
					}
					N := big.NewInt(0)
					for l := 0; l < numberOfExtendPrime; l++ {
						temp := new(big.Int).Mul(bjxjExtend[l], NijList[l])
						N.Add(N, temp)
						N.Mod(N, exptendProduct)
					}

					pMod4 := int64(0)
					qMod4 := int64(0)
					for z := 0; z < n; z++ {
						pMod4 += pMod4List[z]
						qMod4 += qMod4List[z]
					}
					if !checkDivisible(N, divisibleIndex) {
						for z := 0; z < n; z++ {
							partyList[z].N = new(big.Int).Set(N)
							partyList[z].pMod4 = pMod4
							partyList[z].qMod4 = qMod4
							epsilonP := big.NewInt(1)
							epsilonQ := big.NewInt(1)
							if pMod4 == 1 {
								epsilonP.Neg(epsilonP)
							}
							if qMod4 == 1 {
								epsilonQ.Neg(epsilonQ)
							}
							partyList[z].epsilonP = epsilonP
							partyList[z].epsilonQ = epsilonQ
							partyList[z].epsilonN = new(big.Int).Mul(epsilonP, epsilonQ)
						}
						break
					} else {
						// Reset
						for z := 0; z < n; z++ {
							partyList[z], _ = NewBFSampling(n, numberOfPrime, z == 0)
						}
					}
				}

				N = new(big.Int).Set(partyList[0].N)
				// check
				randomList := make([]*big.Int, n)
				piqiTwist := make([]*big.Int, n)
				for z := 0; z < n; z++ {
					randomList[z], _ = utils.RandomInt(N)
					temp := make([]*big.Int, n)
					temp[z] = new(big.Int).Set(partyList[z].pi)
					piqiTwist[z] = new(big.Int).Set(partyList[z].qi)

					if partyList[0].epsilonQ.Cmp(big1) != 0 {
						temp[z].Neg(temp[z])
					}
					if partyList[0].epsilonP.Cmp(big1) != 0 {
						piqiTwist[z].Neg(piqiTwist[z])
					}
					piqiTwist[z] = piqiTwist[z].Add(piqiTwist[z], temp[z])
					piqiTwist[z].Add(piqiTwist[z], partyList[z].epsilonN)
					piqiTwist[z].Mod(piqiTwist[z], N)
				}
				gcdResult := MPCGCD(randomList, piqiTwist, LagrangeCoefficient, N)
				if gcdResult.Cmp(big1) != 0 {
					// fmt.Println("gcdResultNot1:", gcdResult)
					// Reset
					for z := 0; z < n; z++ {
						partyList[z], _ = NewBFSampling(n, numberOfPrime, z == 0)
					}
					continue
				}

				count := 0
				leakCount := 0
				bigLowerLength := 80
				uMessageList := make([]*big.Int, n)
				vMessageList := make([]*big.Int, n)
				sSquarePList := make([]*big.Int, n)

				var err error
				for k := 0; k < 80; k++ {
					var P *big.Int
					var copyD, D *big.Int
					countLeak := 0
					for q := 0; q < maxRetry; q++ {
						D, err := rand.Prime(rand.Reader, bigLowerLength)
						if err != nil {
							continue
						}

						negD := new(big.Int).Neg(D)

						if big.Jacobi(negD, N) == -1 {
							continue
						}

						sShares := make([]*big.Int, n)
						pList := make([]*big.Int, n)
						for z := 0; z < n; z++ {
							sShares[z], _ = utils.RandomInt(D)
							pList[z] = partyList[z].pi
						}

						// Generate all shares
						sSquarePList = MPCMulShamir(sShares, sShares, LagrangeCoefficient, D)
						sSquarePList = MPCMulShamir(sSquarePList, pList, LagrangeCoefficient, D)
						sSquare := big.NewInt(0)
						for z := 0; z < n; z++ {
							sSquare.Add(sSquare, sSquarePList[z])
						}
						sSquare.Mod(sSquare, D)
						countLeak++
						P, err = generateRamdonP(bigLowerLength, int(partyList[0].pMod4), D, sSquare, N)
						if err == nil {
							copyD = new(big.Int).Set(D)
							break
						}
					}
					D = copyD
					for z := 0; z < n; z++ {
						u, v := partyList[z].computeLucasMatrice(D, P)
						partyList[z].shuffleElement(u, v, D, N)
					}

					for z := 0; z < n; z++ {
						tempU := big.NewInt(1)
						tempV := big.NewInt(0)
						for w := 0; w < n; w++ {
							tempU, tempV = specialMul(tempU, tempV, partyList[w].UsendShuffle[z], partyList[w].VsendShuffle[z], D, N)
						}
						uMessageList[z] = tempU
						vMessageList[z] = tempV
					}

					for z := 0; z < n; z++ {
						err = partyList[z].CheckLucasCongruence(uMessageList, vMessageList, D)
						if err != nil {
							break
						}
					}
					if err != nil {
						//fmt.Println("failure", j)
						break
					} else {
						leakCount += countLeak
						count++
						//fmt.Println("maybeOK")
						continue
					}
				}
				if count > 79 {
					end := time.Since(start).String()
					if p.ProbablyPrime(10) && q.ProbablyPrime(10) {
						timeList[m] = end
						leakCountList[m] = leakCount
					} else {
						//timeList[m] = "failure"
						leakCountList[m] = leakCount
					}
					// fmt.Println("p:", p)
					// fmt.Println("q:", q)
					fmt.Println("Complete", m)
					break
				} else {
					if j == maxTry-2 {
						timeList[m] = "failure"
						leakCountList[m] = -1
					}
					// Reset
					for z := 0; z < n; z++ {
						partyList[z], _ = NewBFSampling(n, numberOfPrime, z == 0)
					}
				}
			}
		}
		fmt.Println("timeList:", timeList)
		fmt.Println("leakCountList:", leakCountList)
	})

	FIt("Boneh-Franklin Biprimality test", func() {
		// 30, 56, 1
		// 2048: 131, 235, 17; 3072: 183, 329, 25
		var p, q, N *big.Int
		numberOfPrime := 131
		numberOfExtendPrime := 235
		divisibleIndex := 17
		n := 2
		// Chinese Recover (Compute p and q)
		bjxj, product := chineseRecover(numberOfPrime)
		partyList := make([]*BiPrimeManage, n)
		tryTime := 80

		// Chinese Recover (Now use extend)
		bjxjExtend, exptendProduct := chineseRecover(numberOfExtendPrime)
		diffNumberPrime := numberOfExtendPrime - numberOfPrime
		timeList := make([]string, tryTime)
		LagrangeCoefficient := make([]*big.Int, (2*n)-1)
		LagrangeCoefficientInt64 := make([]int64, (2*n)-1)
		maxTry := 20000

		for i := 0; i < len(LagrangeCoefficient); i++ {
			bigI := big.NewInt(int64(i + 1))
			tempUp := big.NewInt(1)
			tempLower := big.NewInt(1)
			for j := 0; j < len(LagrangeCoefficient); j++ {
				if j != i {
					bigJ := big.NewInt(int64(j) + 1)
					temp := new(big.Int).Neg(bigJ)
					tempUp.Mul(tempUp, temp)
					tempLower.Mul(tempLower, new(big.Int).Sub(bigI, bigJ))
				}
			}
			LagrangeCoefficient[i] = new(big.Int).Div(tempUp, tempLower)
			LagrangeCoefficientInt64[i] = LagrangeCoefficient[i].Int64()
		}

		for m := 0; m < tryTime; m++ {
			start := time.Now()
			// Initial all parties
			for z := 0; z < n; z++ {
				partyList[z], _ = NewBFSampling(n, numberOfPrime, z == 0)
			}
			for j := 0; j < maxTry; j++ {
				for i := 0; i < 4000; i++ {
					for l := 1; l < numberOfPrime; l++ {
						piList := make([]int64, n)
						qiList := make([]int64, n)
						rList := make([]int64, n)
						for z := 0; z < n; z++ {
							piList[z] = partyList[z].pij[l]
							qiList[z] = partyList[z].qij[l]
							rList[z] = mathRandom.Int63n(primeList[l])
						}
						piqiList := MPCMulShamirInt64(piList, qiList, LagrangeCoefficientInt64, primeList[l])
						NiGCD := MPCGCDInt64(rList, piqiList, LagrangeCoefficientInt64, primeList[l])
						Ni := int64(0)
						if NiGCD == 1 {
							for z := 0; z < n; z++ {
								Ni += piqiList[z]
							}
							Ni = Ni % primeList[l]
						}
						if Ni != 0 {
							for z := 0; z < n; z++ {
								partyList[z].Nj[l] = Ni
							}
						} else {
							for try := 0; try < 1000; try++ {
								// Refresh divide part
								Refreshpij := make([]int64, n)
								Refreshqij := make([]int64, n)
								for z := 0; z < n; z++ {
									Refreshpij[z] = mathRandom.Int63n(primeList[l])
									Refreshqij[z] = mathRandom.Int63n(primeList[l])
									rList[z] = mathRandom.Int63n(primeList[l])
								}
								piqiList := MPCMulShamirInt64(Refreshpij, Refreshqij, LagrangeCoefficientInt64, primeList[l])
								NiGCD := MPCGCDInt64(rList, piqiList, LagrangeCoefficientInt64, primeList[l])
								Ni := int64(0)
								if NiGCD == 1 {
									for z := 0; z < n; z++ {
										Ni += piqiList[z]
									}
									Ni = Ni % primeList[l]
								}
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

					// CRT
					p = big.NewInt(0)
					q = big.NewInt(0)
					for z := 0; z < n; z++ {
						tempPi := big.NewInt(0)
						tempQi := big.NewInt(0)
						for l := 0; l < numberOfPrime; l++ {
							pi := big.NewInt(partyList[z].pij[l])
							temp := new(big.Int).Mul(bjxj[l], pi)
							tempPi.Add(tempPi, temp)
							tempPi.Mod(tempPi, product)

							qi := big.NewInt(partyList[z].qij[l])
							temp = new(big.Int).Mul(bjxj[l], qi)
							tempQi.Add(tempQi, temp)
							tempQi.Mod(tempQi, product)
						}

						partyList[z].pi = tempPi
						partyList[z].qi = tempQi
						// just Use in Modify
						p.Add(p, tempPi)
						q.Add(q, tempQi)
					}

					// MPC CRT extend
					for z := 0; z < n; z++ {
						tempExpendP := make([]int64, diffNumberPrime)
						tempExpendQ := make([]int64, diffNumberPrime)
						for w := numberOfPrime; w < numberOfExtendPrime; w++ {
							startIndex := w - numberOfPrime
							prime := big.NewInt(primeList[w])
							tempExpendP[startIndex] = (new(big.Int).Mod(partyList[z].pi, prime)).Int64()

							tempExpendQ[startIndex] = (new(big.Int).Mod(partyList[z].qi, prime)).Int64()
						}
						partyList[z].pij = append(partyList[z].pij, tempExpendP...)
						partyList[z].qij = append(partyList[z].qij, tempExpendQ...)
					}

					// Locally product
					NijList := make([]*big.Int, numberOfExtendPrime)
					for w := 0; w < numberOfExtendPrime; w++ {
						pijList := make([]*big.Int, n)
						qijList := make([]*big.Int, n)
						for z := 0; z < n; z++ {
							pijList[z] = big.NewInt(partyList[z].pij[w])
							qijList[z] = big.NewInt(partyList[z].qij[w])
						}
						prime := big.NewInt(primeList[w])
						partyLocalProductShare := MPCMulShamir(pijList, qijList, LagrangeCoefficient, prime)

						Nij := big.NewInt(0)
						for z := 0; z < n; z++ {
							Nij.Add(partyLocalProductShare[z], Nij)
						}
						Nij.Mod(Nij, prime)
						NijList[w] = Nij
					}
					N := big.NewInt(0)
					for l := 0; l < numberOfExtendPrime; l++ {
						temp := new(big.Int).Mul(bjxjExtend[l], NijList[l])
						N.Add(N, temp)
						N.Mod(N, exptendProduct)
					}

					if !checkDivisible(N, divisibleIndex) {
						for z := 0; z < n; z++ {
							partyList[z].N = new(big.Int).Set(N)
						}
						break
					} else {
						// Reset
						for z := 0; z < n; z++ {
							partyList[z], _ = NewBFSampling(n, numberOfPrime, z == 0)
						}
					}
				}

				N = new(big.Int).Set(partyList[0].N)
				// check
				randomList := make([]*big.Int, n)
				piqiTwist := make([]*big.Int, n)
				for z := 0; z < n; z++ {
					randomList[z], _ = utils.RandomInt(N)
					temp := make([]*big.Int, n)
					temp[z] = new(big.Int).Set(partyList[z].pi)
					piqiTwist[z] = new(big.Int).Set(partyList[z].qi)

					piqiTwist[z] = piqiTwist[z].Add(piqiTwist[z], temp[z])
					piqiTwist[z].Add(piqiTwist[z], big1)
					piqiTwist[z].Mod(piqiTwist[z], N)
				}
				gcdResult := MPCGCD(randomList, piqiTwist, LagrangeCoefficient, N)
				if gcdResult.Cmp(big1) != 0 {
					// Reset
					for z := 0; z < n; z++ {
						partyList[z], _ = NewBFSampling(n, numberOfPrime, z == 0)
					}
					continue
				}

				NMinus1 := new(big.Int).Sub(N, big1)
				count := 0
				for k := 0; k < 80; k++ {
					var g *big.Int
					for q := 0; q < maxRetry; q++ {
						g = big.NewInt(0)
						for z := 0; z < n; z++ {
							tempgi, err := utils.RandomInt(N)
							g.Add(tempgi, g)
							g.Mod(g, N)
							Expect(err).Should(BeNil())
							partyList[z].gi = tempgi
						}
						if utils.Gcd(g, N).Cmp(big1) != 0 {
							continue
						}
						if big.Jacobi(g, N) == 1 {
							break
						}
					}

					viList := make([]*big.Int, len(partyList))
					for z := 0; z < n; z++ {
						viList[z] = partyList[z].computeBonehExponent(g)
					}
					isAllOK := true
					for z := 0; z < n; z++ {
						checkValue := new(big.Int).Set(viList[0])
						for q := 1; q < len(viList); q++ {
							checkValue.Mul(checkValue, viList[q])
							checkValue.Mod(checkValue, N)
						}
						if checkValue.Cmp(big1) != 0 && checkValue.Cmp(NMinus1) != 0 {
							isAllOK = false
							break
						}
					}
					if isAllOK {
						count++
					} else {
						break
					}
				}
				if count > 79 {
					end := time.Since(start).String()
					if p.ProbablyPrime(10) && q.ProbablyPrime(10) {
						timeList[m] = end
					} else {
					}
					fmt.Println("Complete", m)
					break
				} else {
					if j == maxTry-2 {
						timeList[m] = "failure"
					}
					// Reset
					for z := 0; z < n; z++ {
						partyList[z], _ = NewBFSampling(n, numberOfPrime, z == 0)
					}
				}
			}
		}
		fmt.Println("timeList:", timeList)
	})
})

func BenchmarkPrintInt2String01(b *testing.B) {
	P, _ := new(big.Int).SetString("5834109160054197041406849888967019098188050229061902322665650864326996974961427172103609558931697802249049073512927249926833569096661182296567798396591108093093565575650932490315293348816198777883821708894912437254809059558193994443986810084421017533300507980425771634277300723149279292762401779746250040488361", 10)
	Q, _ := new(big.Int).SetString("10306565083257177581836484197079439206526967306293322374678336189663373223012534332354084390986709820812271259082355334307464180132168545568673519959502325811798997900643760295590210111624353376540023004091919431098744611476016779827854424030242420021873901749507260599995005956371914294960621572047445451619479", 10)
	N := new(big.Int).Mul(P, Q)
	D, _ := new(big.Int).SetString("802938590925802589920385902850928502385080238590328509328502985023852090238502358290358205029358025802850285020528502850285", 10)

	exp2 := new(big.Int).Sub(N, big1)
	//u2, v2 := specialExp(big.NewInt(2), big.NewInt(1), D, N, exp2)
	for i := 0; i < b.N; i++ {
		Exp(big.NewInt(2935802850205802), big.NewInt(2385927592), D, N, exp2)
	}
}

func BenchmarkExpSquareCubic(b *testing.B) {
	P, _ := new(big.Int).SetString("5834109160054197041406849888967019098188050229061902322665650864326996974961427172103609558931697802249049073512927249926833569096661182296567798396591108093093565575650932490315293348816198777883821708894912437254809059558193994443986810084421017533300507980425771634277300723149279292762401779746250040488361", 10)
	Q, _ := new(big.Int).SetString("10306565083257177581836484197079439206526967306293322374678336189663373223012534332354084390986709820812271259082355334307464180132168545568673519959502325811798997900643760295590210111624353376540023004091919431098744611476016779827854424030242420021873901749507260599995005956371914294960621572047445451619479", 10)
	N := new(big.Int).Mul(P, Q)
	D, _ := new(big.Int).SetString("802938590925802589920385902850928502385080238590328509328502985023852090238502358290358205029358025802850285020528502850285", 10)

	exp2 := new(big.Int).Sub(N, big1)
	for i := 0; i < b.N; i++ {
		ExpSquareCubic(big.NewInt(2935802850205802), big.NewInt(2385927592), D, N, exp2)
	}
}

func BenchmarkSpecialExp(b *testing.B) {
	P, _ := new(big.Int).SetString("5834109160054197041406849888967019098188050229061902322665650864326996974961427172103609558931697802249049073512927249926833569096661182296567798396591108093093565575650932490315293348816198777883821708894912437254809059558193994443986810084421017533300507980425771634277300723149279292762401779746250040488361", 10)
	Q, _ := new(big.Int).SetString("10306565083257177581836484197079439206526967306293322374678336189663373223012534332354084390986709820812271259082355334307464180132168545568673519959502325811798997900643760295590210111624353376540023004091919431098744611476016779827854424030242420021873901749507260599995005956371914294960621572047445451619479", 10)
	N := new(big.Int).Mul(P, Q)
	D, _ := new(big.Int).SetString("802938590925802589920385902850928502385080238590328509328502985023852090238502358290358205029358025802850285020528502850285", 10)

	exp2 := new(big.Int).Sub(N, big1)
	for i := 0; i < b.N; i++ {
		specialExp(big.NewInt(2935802850205802), big.NewInt(2385927592), D, N, exp2)
	}
}

func TestCrypto(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "MpcRsa Test")
}
