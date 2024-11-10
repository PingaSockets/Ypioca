import { AccountSettings, BaileysEvent, BaileysEventEmitter, ChatMutation, Contact, InitialAppStateSyncOptions } from '../Types'
import { unixTimestampSeconds } from '../Utils'
import { processSyncAction } from '../Utils/chat-utils'
import logger from '../Utils/logger'
import { randomJid } from './utils';

describe('App State Sync Tests', () => {

	const me: Contact = { id: randomJid() }
  /**
   * ENG: case when initial sync is off
	 * Caso em que a sincronização inicial está desligada.
	 * Deve retornar um evento de arquivamento com `archived=false`.
	 */
	it('should return archive=false event', () => {
		const jid = randomJid()
		const index = ['archive', jid]

    // CASO: Testando alterações de arquivamento para eventos diferentes
         const CASES: ChatMutation[][] = [
            [
                {
                    index,
                    syncAction: {
                        value: {
                            archiveChatAction: {
                                archived: false,
                                messageRange: {
                                    lastMessageTimestamp: unixTimestampSeconds()
                                }
                            }
                        }
                    }
                }
            ],
            [
                {
                    index,
                    syncAction: {
                        value: {
                            archiveChatAction: {
                                archived: true,
                                messageRange: {
                                    lastMessageTimestamp: unixTimestampSeconds()
                                }
                            }
                        }
                    }
                },
                {
                    index,
                    syncAction: {
                        value: {
                            archiveChatAction: {
                                archived: false,
                                messageRange: {
                                    lastMessageTimestamp: unixTimestampSeconds()
                                }
                            }
                        }
                    }
                }
            ]
        ];

    // Processa cada cenário de `CASES`
    for(const mutations of CASES) {
      for (const mutation of mutations) {
            const events = processSyncAction(mutation, "chats.update", me, undefined, logger);
            expect(events['chats.update']).toHaveLength(1);
            const event = events['chats.update']?.[0];
            expect(event.archive).toEqual(false); // Espera que 'archive' seja falso
      }
    }
	})
	// 
  /**
   * ENG: case when initial sync is on and unarchiveChats = true
    * Caso a sincronização inicial está ligada 
    * e `unarchiveChats` é verdadeiro. 
    * Não deve disparar nenhum evento de arquivamento.
  */
	it('should not fire any archive event', () => {
		const jid = randomJid()
		const index = ['archive', jid]
		const now = unixTimestampSeconds()

		const CASES: ChatMutation[][] = [
			[
				{
					index,
					syncAction: {
						value: {
							archiveChatAction: {
								archived: true,
								messageRange: {
									lastMessageTimestamp: now - 1
								}
							}
						}
					}
				}
			],
			[
				{
					index,
					syncAction: {
						value: {
							archiveChatAction: {
								archived: false,
								messageRange: {
									lastMessageTimestamp: now + 10
								}
							}
						}
					}
				}
			],
			[
				{
					index,
					syncAction: {
						value: {
							archiveChatAction: {
								archived: true,
								messageRange: {
									lastMessageTimestamp: now + 10
								}
							}
						}
					}
				},
				{
					index,
					syncAction: {
						value: {
							archiveChatAction: {
								archived: false,
								messageRange: {
									lastMessageTimestamp: now + 11
								}
							}
						}
					}
				}
			],
		]

		const ctx: InitialAppStateSyncOptions = {
			accountSettings: { unarchiveChats: true }
		}

		for(const mutations of CASES) {
      for (const mutation of mutations) {
			const events = processSyncAction(mutation, "chats.update", me, ctx, logger)
			expect(events['chats.update']?.length).toBeFalsy()
      }
		}
	})

	// case when initial sync is on
	// with unarchiveChats = true & unarchiveChats = false
  /**
     * Testa o caso em que a sincronização inicial está ligada 
     * com `unarchiveChats` sendo verdadeiro e falso.
     * Deve disparar eventos de arquivamento com `archived=true`.
     */
	it('should fire archive=true events', () => {
		const jid = randomJid()
		const index = ['archive', jid]
		const now = unixTimestampSeconds()

		const CASES: { settings: AccountSettings, mutations: ChatMutation[] }[] = [
			{
				settings: { unarchiveChats: true },
				mutations: [
					{
						index,
						syncAction: {
							value: {
								archiveChatAction: {
									archived: true,
									messageRange: {
										lastMessageTimestamp: now
									}
								}
							}
						}
					}
				],
			},
			{
				settings: { unarchiveChats: false },
				mutations: [
					{
						index,
						syncAction: {
							value: {
								archiveChatAction: {
									archived: true,
									messageRange: {
										lastMessageTimestamp: now - 10
									}
								}
							}
						}
					}
				],
			}
		]

		for(const { mutations, settings } of CASES) {
			const ctx: InitialAppStateSyncOptions = {
				accountSettings: settings
			}
      for (const mutation of mutations) {        
			const events = processSyncAction(mutation, "chats.update", me, ctx, logger)
			expect(events['chats.update']).toHaveLength(1)
			const event = events['chats.update']?.[0]
			expect(event.archive).toEqual(true)
      }
		}
	})
})