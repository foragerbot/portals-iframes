// sdk/wrapper for portals related functionality

const PortalsSdk = {
    PortalsWindow: window,
    PortalsParent: parent,
    PortalsSdkLocation: "PortalsSdk",
  
    Origin: {
      Localhost: "http://localhost:3000",
      Dev: "https://dev.theportal.to",
      Prev: "https://preview.theportal.to",
      Prod: "https://theportal.to",
      Staging: "https://deploy-preview-114--portal-backend.netlify.app",
      Staging2: "https://deploy-preview-117--portal-backend.netlify.app"
    },
  
    Callbacks: {
      publicKey: null,
      publicId: null,
      requestItem: null,
      getItemData: null,
      sellItem: null,
      getInventoryData: null,
      getUserQuests: null,
      startQuest: null,
      getCompletedQuest: null,
      addDrone: null,
      getDroneData: null,
      getRoomId: null,
      claimZone: null,
      getZones: null,
      isLoggedIn: null,
      claimOneKin: null,
      onTranscription: null,
      onSpeechVolume: null,
      getPassagesAudio: null,
      onTransaction: null,
      getWelcomeEmbedNotes: null,
      sessionGet: null
    },
    currencyId: null, //Defaults to Portals Credits currency
    voiceId: null,
    Story: null,
    NPCs: {
      "kOSgMDTb3Z8cO4r89w2I": {
        name: "Professor Quibbly",
        img: "https://cdn.glitch.global/6cab8115-fec2-467a-95e5-0fb02f393f25/quibbly.png?v=1704323329585",
      },
      "JBFqnCBsd6RMkjVDRZzb": {
        name: "Forest Shepard",
        img: "https://cdn.glitch.global/6cab8115-fec2-467a-95e5-0fb02f393f25/forest.png?v=1704395968772",
      },
      "SOYHLrjzK2X1ezoPC6cr": {
        name: "Joey",
        img: "https://cdn.glitch.global/164bafb1-0268-4ed8-a63a-3f1451191c7d/image.png?v=1707934652823",
      }
    },
  
    OnMessage: (e) => {
      if (typeof e.data === 'string' && e.data.startsWith("requestedPublicKey:")) {
        let publicKey = e.data.split(":")[1];
        PortalsSdk.Callbacks.publicKey(publicKey);
      }
      if (typeof e.data === 'string' && e.data.startsWith("requestedPublicId:")) {
        let publicId = e.data.split(":")[1];
        PortalsSdk.Callbacks.publicId(publicId);
      }
      if (e.data.groupedItems && e.data.type == "buy" && (e.data.success != null || e.data.error != null)) {
        PortalsSdk.Callbacks.requestItem(e.data);
      }
      if (e.data.itemData) {
        PortalsSdk.Callbacks.getItemData(e.data);
      }
      if (e.data.groupedItems && e.data.type == "sell" && (e.data.success != null || e.data.error != null)) {
        PortalsSdk.Callbacks.sellItem(e.data);
      }
      if (PortalsSdk.Callbacks.getInventoryData != null && e.data.groupedItems && !e.data.type) {
        PortalsSdk.Callbacks.getInventoryData(e.data);
      }
      if (e.data.quests) {
        PortalsSdk.Callbacks.getUserQuests(e.data);
      }
      if ((e.data.createdQuest && !e.data.completed) || (e.data.createdQuest == null && e.data.error)) {
        PortalsSdk.Callbacks.startQuest(e.data);
      }
      if (e.data.createdQuest && e.data.completed){
         PortalsSdk.Callbacks.getCompletedQuest(e.data);
      }
      if (e.data.drone) {
        PortalsSdk.Callbacks.addDrone(e.data);
      }
      if (e.data.userDrones) {
        PortalsSdk.Callbacks.getDroneData(e.data);
      }
      if (e.data.roomId) {
        PortalsSdk.Callbacks.getRoomId(e.data);
      }
      if (e.data.claimedZone) {
        PortalsSdk.Callbacks.claimZone(e.data);
      }
      if (e.data.zones) {
        PortalsSdk.Callbacks.getZones(e.data);
      }
      if (e.data.isLoggedInResponse) {
        PortalsSdk.Callbacks.isLoggedIn(e.data.isLoggedInResponse);
      }
      if (e.data.onekin) {
        PortalsSdk.Callbacks.claimOneKin(e.data);
      }
      if (e.data.transcription) {
        PortalsSdk.Callbacks.onTranscription(e.data);
      }
      if (e.data.speechVolume) {
        PortalsSdk.Callbacks.onSpeechVolume(e.data);
      }
      if (e.data.passagesAudio) {
        PortalsSdk.Callbacks.getPassagesAudio(e.data.passagesAudio);
      }
      if (e.data.transaction) {
        PortalsSdk.Callbacks.onTransaction(e.data.transaction);
      }
      if (e.data.welcomeEmbedNotes) {
        PortalsSdk.Callbacks.getWelcomeEmbedNotes(e.data.welcomeEmbedNotes);
      }
      if (e.data.sessionGet) {
        PortalsSdk.Callbacks.sessionGet(e.data.sessionGet);
      }
      if (e.data.portalsMessage) {
        PortalsSdk.Callbacks.messageListener(e.data.portalsMessage);
      }
    },
    // originUrl: url of the portals (examples: https://dev.theportal.to, https://theportal.to)
    requestPublicKey(originUrl, callback) {
      PortalsSdk.Callbacks.publicKey = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        'publicKeyRequest',
        originUrl);
  
      console.log("public key requested");
    },
  
    requestPublicId(originUrl, callback) {
      PortalsSdk.Callbacks.publicId = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        'publicIdRequest',
        originUrl);
      
      location.href = "uniwebview://action?type=publicIdRequest&location="+PortalsSdk.PortalsSdkLocation;
  
      console.log("public id requested");
    },
  
    requestItemTr(originUrl, generatorId, wallet, publicId, count, transaction, notiMsg, notiSound, callback) {
      PortalsSdk.Callbacks.requestItem = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      let n = count || 1;
  
      PortalsSdk.PortalsParent.postMessage(
        {
          generatorId: generatorId,
          userId: wallet,
          publicId: publicId,
          count: n,
          transaction: transaction,
          notiMsg: notiMsg,
          notiSound: notiSound,
          currency: PortalsSdk.currencyId
        },
        originUrl);
      
      var url = "uniwebview://action?type=requestItem&count="+n+"&userId="+wallet+"&generatorId="+generatorId+"&publicId="+publicId+
          "&notiMsg="+notiMsg+"&notiSound="+notiSound+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("item to user inventory requested");
    },

    requestItem(originUrl, generatorId, wallet, publicId, count, notiMsg, notiSound, callback) {
      PortalsSdk.requestItemTr(originUrl, generatorId, wallet, publicId, count, "", notiMsg, notiSound, callback);
    },
  
    getItemData(originUrl, keys, publicId, callback) {
      PortalsSdk.Callbacks.getItemData = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        {
          keys,
          type: 'itemData',
          publicId: publicId,
          currency: PortalsSdk.currencyId
        },
        originUrl);
  
      var url = "uniwebview://action?type=itemData&publicId="+publicId+"&location="+PortalsSdk.PortalsSdkLocation;
      keys.forEach(function (str, index) {
        url += "&keys="+str;
      });
      location.href = url;
      
      console.log("item data requested");
    },
  
    sellItem(originUrl, id, itemGeneratorId, wallet, publicId, amount, callback) {
      PortalsSdk.Callbacks.sellItem = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      console.log("SELL ID: " + id, currentMachine);
      PortalsSdk.PortalsParent.postMessage(
        {
          type: "sell",
          itemId: id,
          userId: wallet,
          publicId: publicId,
          itemGeneratorId: itemGeneratorId,
          amount,
          currency: PortalsSdk.currencyId
        },
        originUrl);
      
      var url = "uniwebview://action?type=sell&itemId="+id+"&userId="+wallet+"&itemGeneratorId="+itemGeneratorId+
          "&publicId="+publicId+"&amount="+amount+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("item sell requested");
  
    },
  
    getInventoryData(originUrl, itemGeneratorKeys, itemGeneratorIds, callback, extraItems = false) {
      PortalsSdk.Callbacks.getInventoryData = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      PortalsSdk.PortalsParent.postMessage(
        {
          type: 'inventory',
          itemGeneratorKeys: itemGeneratorKeys,
          itemGeneratorIds: itemGeneratorIds,
          currency: PortalsSdk.currencyId,
          extraItems: extraItems
        },
        originUrl);
      
      var url = "uniwebview://action?type=inventory&location="+PortalsSdk.PortalsSdkLocation;
      if(itemGeneratorKeys.length == 0){
        url += "&itemGeneratorKeys=null";
      }else{
        itemGeneratorKeys.forEach(function (str, index) {
            url += "&itemGeneratorKeys="+str;
          });
      }
      if(!itemGeneratorIds || itemGeneratorIds.length == 0){
        url += "&itemGeneratorIds=null";
      }else{
        itemGeneratorIds.forEach(function (str, index) {
            url += "&itemGeneratorIds="+str;
          });
      }
      url += "&currency="+PortalsSdk.currencyId;
      url += "&extraItems="+extraItems;
      location.href = url;
  
      console.log("inventory requested");
    },
  
    getUserQuests(groupIds, activeQuests, publicId, callback) {
      PortalsSdk.Callbacks.getUserQuests = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        {
          "type": "userQuests",
          "groupIds": groupIds,
          "publicId": publicId,
          "activeQuests": activeQuests
        },
        "*");
      
      var url = "uniwebview://action?type=userQuests&publicId="+publicId+
          "&activeQuests="+activeQuests+"&location="+PortalsSdk.PortalsSdkLocation;
      
      groupIds.forEach(function (str, index) {
        url += "&groupIds="+str;
      });
      location.href = url;
  
      console.log("get user quests requested", groupIds);
    },
  
    startQuest(originUrl, questId, publicId, notiMsg, notiSound, callback) {
      PortalsSdk.Callbacks.startQuest = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        {
          "questId": questId,
          "publicId": publicId,
          "notiMsg": notiMsg,
          "notiSound": notiSound
        },
        originUrl);
      
      var url = "uniwebview://action?type=startQuest&questId="+questId+"&publicId="+publicId+
          "&notiMsg="+notiMsg+"&notiSound="+notiSound+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("start quest requested");
    },
    
    getCompletedQuest(originUrl, questId, publicId, notiMsg, notiSound, callback) {
      PortalsSdk.Callbacks.getCompletedQuest = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      
      PortalsSdk.PortalsParent.postMessage(
        {
          type: 'completeQuest',
          "questId": questId,
          "publicId": publicId,
          "notiMsg": notiMsg,
          "notiSound": notiSound
        },
        originUrl);
      
      var url = "uniwebview://action?type=completeQuest&questId="+questId+"&publicId="+publicId+
          "&notiMsg="+notiMsg+"&notiSound="+notiSound+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("complete quest requested");
    },
  
    addDrone(publicId, droneId, callback) {
      PortalsSdk.Callbacks.addDrone = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
  
      PortalsSdk.PortalsParent.postMessage(
        {
          "type": "addDrone",
          "publicId": publicId,
          "droneId": droneId,
        },
        "*");
      
      var url = "uniwebview://action?type=addDrone&droneId="+droneId+"&publicId="+publicId+
          "&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("get drone requested");
    },
    
    getDroneData(publicId, callback) {
      PortalsSdk.Callbacks.getDroneData = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      
      PortalsSdk.PortalsParent.postMessage(
        {
          type: 'droneData',
          publicId: publicId
        },
        "*");
      
      var url = "uniwebview://action?type=droneData&publicId="+publicId+
          "&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("get drone data requested");
    },
  
    getRoomId(callback) {
      PortalsSdk.Callbacks.getRoomId = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        {
          "type": "getRoomId"
        },
        "*");
  
      console.log("room id requested");
    },
  
    claimOneKin(claimCode, collectibleId, callback) {
      PortalsSdk.Callbacks.claimOneKin = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        {
         "claimCode": claimCode,
         "collectibleId": collectibleId
        },
        "*");
      var url = "uniwebview://action?claimCode="+claimCode+"&collectibleId="+collectibleId+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("claim one kin requested");
    },
  
    startSpeechToText(prompt, liveTranscription, speechTime, transcriptionCb, speechVolumeCb) {
      PortalsSdk.Callbacks.onTranscription = transcriptionCb;
      PortalsSdk.Callbacks.onSpeechVolume = speechVolumeCb;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage({
        "startSpeechToText": true,
        "prompt": prompt,
        "liveTranscription": liveTranscription,
        "speechTime": speechTime
      },
        "*");
      var url = "uniwebview://action?startSpeechToText=true&prompt="+encodeURIComponent(prompt)+"&liveTranscription="+liveTranscription+"&speechTime="+speechTime+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("start speech to text");
    },
  
    stopSpeechToText() {
      PortalsSdk.PortalsParent.postMessage("stopSpeechToText",
        "*");
      var url = "uniwebview://action?stopSpeechToText=true&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("stop speech to text requested");
    },
  
    startTextToSpeech(text, story = "", passage = "") {
      PortalsSdk.PortalsParent.postMessage({
        "doTextToSpeech": true,
        "text": text,
        "story": story,
        "passage": passage  
      },
        "*");
      var url = "uniwebview://action?doTextToSpeech=true&text="+encodeURIComponent(text)+"&story="+encodeURIComponent(story)+"&passage="+encodeURIComponent(passage)+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("start text to speech");
    },
  
    claimZone(zoneId, publicId, callback) {
      PortalsSdk.Callbacks.claimZone = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        {
         "zoneId": zoneId,
          "publicId": publicId
        },
        "*");
      var url = "uniwebview://action?zoneId="+zoneId+"&publicId="+publicId+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("claim plot requested");
    },
  
    getZones(forRoom, publicId, callback) {
      PortalsSdk.Callbacks.getZones = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        {
          "forRoom": forRoom,
          "type": "getZones",
          "publicId": publicId
        },
        "*");
      
      var url = "uniwebview://action?forRoom="+forRoom+"&publicId="+publicId+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
  
      console.log("get zones requested");
    },

    doSolTransaction(wallet, token, amount, callback) {
      PortalsSdk.Callbacks.onTransaction = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
  
      PortalsSdk.PortalsParent.postMessage(
        {
          "type": "transaction",  
          "wallet": wallet,
          "token": token,
          "amount": amount,
        },
        "*");
      
      //var url = "uniwebview://action?forRoom="+forRoom+"&publicId="+publicId+"&location="+PortalsSdk.PortalsSdkLocation;
      //location.href = url;
  
      console.log("do transaction requested");
    },
  
    getWelcomeEmbedNotes(callback) {
      PortalsSdk.Callbacks.getWelcomeEmbedNotes = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      
      PortalsSdk.PortalsParent.postMessage({
        type: "getWelcomeEmbedNotes",
      },
        "*");
  
      console.log("get welcome embed notes requested");
    },
  
    setWelcomeEmbedNotes(noteIds) {
  
      PortalsSdk.PortalsParent.postMessage({
        type: "setWelcomeEmbedNotes",
        noteIds: noteIds
      },
        "*");
  
      console.log("set welcome embed notes requested");
    },
  
    setWelcomeEmbedNote(noteId, noteRead) {
  
      PortalsSdk.PortalsParent.postMessage({
        type: "setWelcomeEmbedNote",
        noteId: noteId,
        noteRead: noteRead
      },
        "*");
  
      console.log("set welcome embed note requested");
    },
  
    openBackpack() {
  
      PortalsSdk.PortalsParent.postMessage({
        "openBackpack": true
      },
        "*");
  
      console.log("openBackpack requested");
    },
    openInvite() {
      
      PortalsSdk.PortalsParent.postMessage({
          "openInvite": true
        },
        "*");
  
      console.log("openInvite requested");
    },
    showCloseBtn(show) {
      PortalsSdk.PortalsParent.postMessage({
        "reference": "SHOW_CLOSE_BTN",
        "show": show
      },
        "*");
  
      console.log("show btn requested");
    },
    //LOG IN DEFAULT
    openAuthModal() {
  
      PortalsSdk.PortalsParent.postMessage({
        "reference": "OPEN_AUTH_MODAL"
      },
        "*");
  
      console.log("showAuthModal requested");
    },
    //SIGN UP DEFAULT
    openSignupModal() {
  
      PortalsSdk.PortalsParent.postMessage({
        "showSignupModal": true
      },
        "*");
  
      console.log("showSignupModal requested");
    },
  
    sendMessageToUnity(message) {
      PortalsSdk.PortalsParent.postMessage({
        "type": "generic",
        "message": message
      },
        "*");
      
      var url = "uniwebview://action?generic=true&message="+encodeURIComponent(message)+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
      console.log("send message to unity requested");
    },
    setOnCloseIframeMessage(message) {
      PortalsSdk.PortalsParent.postMessage({
        "type": "onCloseIframeMessage",
        "message": message
      },
        "*");
      
      var url = "uniwebview://action?onCloseIframeMessage=true&message="+encodeURIComponent(message)+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
      console.log("set on close iframe message");
    },
    closeIframe() {
      PortalsSdk.PortalsParent.postMessage("closeIframe:" + window.location.href,
        "*");
      
      var url = "uniwebview://action?closeIframe=true&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
      console.log("close iframe v2 requested");
    },

    focusGameKeyboard() {
      PortalsSdk.PortalsParent.postMessage("focusGameKeyboard",
        "*");
        
      console.log("focusGameKeyboard");
    },

    playSound(link) {
      PortalsSdk.PortalsParent.postMessage({
        "type": "playSound",
        "link": link
      },
        "*");
      
      var url = "uniwebview://action?type=playSound&link="+encodeURIComponent(link)+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
      console.log("play sound requested");
    },
    
    isLoggedIn(callback) {
      PortalsSdk.Callbacks.isLoggedIn = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      
      PortalsSdk.PortalsParent.postMessage({
        "isLoggedIn": true
      },
        "*");
    },

    isLoggedInWithWallet(callback) {
      PortalsSdk.Callbacks.isLoggedIn = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      
      PortalsSdk.PortalsParent.postMessage({
        "isLoggedInWithWallet": true
      },
        "*");
    },

    isLoggedInWithWalletSoft(callback) {
      PortalsSdk.Callbacks.isLoggedIn = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      
      PortalsSdk.PortalsParent.postMessage({
        "isLoggedInWithWallet": true,
        "soft": true
      },
        "*");
    },

    sessionSet(key, value) {
      PortalsSdk.PortalsParent.postMessage({
        reference: "SESSION_SET",
        key: key,
        value: value
      },
        "*");
    },

    sessionGet(key, callback) {
      PortalsSdk.Callbacks.sessionGet = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
      
      PortalsSdk.PortalsParent.postMessage({
        reference: "SESSION_GET",
        key: key,
      },
        "*");
    },

    setMessageListener(callback) {
      PortalsSdk.Callbacks.messageListener = callback;
      PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage;
    },
    
    async saveAudio() {
      const passages = PortalsSdk.Story.lookup("tags", "DialogueV2");


      const extractDialogue = function (inputString) {
        // const regexPattern = new RegExp(`${"<span>"}(.*?${"</span>"})`, 's');
        const regexPattern = new RegExp(`${"<span"}[^>]*>(.*?)${"</span>"}`, 's');
        // const regexPattern = new RegExp(`${"<span>"}[^>]*>(.*?)${endTag}`, 's');
  const match = inputString.match(regexPattern);

  return match ? match[1] : null;
      }

      const passageData = passages.map((passage) => {
        const name = passage.title;

        const dialogue = extractDialogue(passage.text);
        // const dialogue = passage.text.substring(passage.text.indexOf("<span>") + 6, passage.text.lastIndexOf("</span>")).trim();

        // console.log(dialogue)
        //console.log(passage.text.replace(/<span>(.*?)<\/span>/g, "$1"));

        let story = PortalsSdk.Story.title.replaceAll(" ", "_");
        const hasVoice = passage.tags.find((el) => el.startsWith('voice:'));
        const voice = typeof hasVoice != 'undefined' ? hasVoice.split('voice:')[1] : PortalsSdk.voiceId
        return {name, dialogue, story, voice};
      })

      PortalsSdk.PortalsParent.postMessage({
        "savePassagesAudio": true,
        "passages": passageData,
      },
        "*");

      var url = "uniwebview://action?savePassagesAudio=true&passages="+encodeURIComponent(passageData)+"&location="+PortalsSdk.PortalsSdkLocation;
      location.href = url;
    },

    textToSpeech(triggerUpdateNpc = true) {
      let currentVoice = null
      
      const updateNPC = function(voiceId){
        if (!triggerUpdateNpc) return;

        const npcImgEl = PortalsSdk.PortalsWindow.document.getElementById('npc-avatar');
        const npcNameEl = PortalsSdk.PortalsWindow.document.getElementById('npc-name');
        const npc = PortalsSdk.NPCs[voiceId];
        //console.log("NPCNPC", npc, npcNameEl);
        
        npcNameEl.innerText = npc.name;
        npcImgEl.src = npc.img;
        currentVoice = voiceId;
      }
      
      //updateNPC(PortalsSdk.voiceId);
      
      $(document).on(':passagerender', function(e) {
        
        const passage = e.passage;
        const content = e.content;
        const tags = passage.tags;
        const dialogue = passage.text.substring(passage.text.indexOf("<span>") + 6, passage.text.lastIndexOf("</span>")).trim();
        const hasVoice = passage.tags.find((el) => el.startsWith('voice:'));
        const voice = typeof hasVoice != 'undefined' ? hasVoice.split('voice:')[1] : PortalsSdk.voiceId
        
        if(currentVoice != voice){
          updateNPC(voice);
        }
        
        if(window.audio){
          window.audio.pause();
        }
        // console.log(e, passage, content, dialogue, PortalsSdk.Story.title);

        if(tags.includes("DialogueV2")){
          PortalsSdk.startTextToSpeech(dialogue, PortalsSdk.Story.title.replaceAll(" ", "_"), passage.title);
        }else if(tags.includes("Dialogue")){
          PortalsSdk.startTextToSpeech(dialogue);
        };
      });
    }
  }