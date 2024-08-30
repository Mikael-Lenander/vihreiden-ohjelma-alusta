Tämä ohjelmisto pohjautuu avoimen lähdekoodin projektiin [Atomic Server](https://atomicserver.eu/). Dokumentaatio löytyy [täältä](https://docs.atomicdata.dev).

## Kehitysympäristön pystytys

1. Asenna [Docker](https://www.docker.com/) ja [docker-compose](https://docs.docker.com/compose/install/).
2. Jos et ole aiemmin ajanut lainkaan ympäristöä, aja `bash start-dev.sh --init`. Tämä pakottaa `atomic-server`in tuomaan sisään `vihreat-data`-kansion sisältämän ohjelmadatan hakemistoon `atomic-storage`, joka liitetään konttiin ja säilyy ajokertojen yli. Jos haluat pakottaa Dockerin rakentamaan kuvat uudestaan, anna skriptille parametri `--build`.
3. Jos olet jo saanut alustettua `atomic-server`in, aja vain `bash start-dev.sh`.
4. Kehitysympäristö ajaa `vihreat-ohjelmat`-sovellusta kehitystilassa, eli koodiin tehdyt muutokset heijastuvat välittömästi [paikalliseen sovellukseen](http://localhost:5176/).
5. Kun olet valmis ja haluat puhdistaa ympäristön kokonaan, aja `bash stop-dev.sh --clean`. Muuten voit vain antaa `CTRL-C` ympäristölle ja ajaa `bash stop-dev.sh`.

## Kehittäminen

Ohjelma-alusta on toteutettu Vite-sovelluksena kansiossa `vihreat-ohjelmat`. 

### `vihreat-data`

Sisältää ontologian (datamallin) määrittelyn sekä työkalun `generate-ld`, jolla ontologia ja muu testidata generoidaan Atomic Serverin ymmärtämään JSON-AD -muotoon

Skripti `initialize-server.sh` alustaa tietokannan ontologialla ja testisisällöllä (olemassa oleva tietokanta tuhoutuu!)

Skripti `generate-ontologies.sh` luo Typescript-tyypit ontologioiden pohjalta ja vie ne suoraan koodiin.

### `vihreat-ohjelmat`

Sisältää ohjelma-alustan asiakassivun. Sivulla voi kuka tahansa (tulevaisuudessa) hakea ja tarkastella ohjelmia. Käynnistä sivu ajamalla:

```sh
bash start-dev.sh
```

Sivu pyörii osoitteessa http://localhost:5176/. 

Sivuston koodin voi ajaa yhdenmukaistuksen (lint) läpi skriptillä `lint-vihreat-ohjelmat.sh`.

## Tuotantopalvelimen ajaminen

1. Päivitä `prod.env` vastaamaan ympäristöä.
2. Aja `bash start-prod.sh`.