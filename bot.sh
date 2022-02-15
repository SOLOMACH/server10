#! /bin/sh
# Kullanım: ./bot.sh
# Kolay kurulum için bir kabuk betiği.
# Fonksiyonlar ve değişkenler tarafından desteklenmektedir.
# İki farklı dil seçeneği mevcuttur.#
# Türk Kullanıcılar İçin
# Türkçe Olmayan Kullanıcılar İçin ( İngilizce )
# ------------------------------------------------- ----------------------------

# İncelenmeyi bekleyen işlevler
:  << ' BEKLEYİN_FOR_İNCELEME '
Ölçek () {
  echo "Konsol Girişi: $1 ve $2"
}
number_one_func () {
   echo "Bu konuşan ilk fonksiyon..."
   iki numaralı
}
number_two_func () {
   echo "Bu şimdi ikinci fonksiyon konuşuyor..."
}
_curl()
{
    yerel cur önceki kelimeler cword
    _init_completion || dönüş
    durumda $önceki
        --soyut-unix-soket | --alt-svc | --yapılandırma | --çerez | \
            --çerez kavanozu | --dump-başlık | --egd dosyası | --etag-karşılaştırma | \
            --etag-save | --hsts | --anahtar | --libcurl | --netrc dosyası | \
            --çıktı | --proxy anahtarı | --rastgele dosya | --iz | --trace-ascii | \
            --unix-soket | --yükleme dosyası | -!(-*)[KbcDoT])
            _filedir
            dönüş
            ;;
        --şifreler | --connect-zaman aşımı | --bağlanmak için | --devam et | \
            --eğriler | --data-ham | --doh-url | --expect100-zaman aşımı | --form | \
            --form-dize | --ftp hesabı | --ftp-kullanıcıya alternatif | \
            --mutlu-gözbebekleri-zaman aşımı-ms | --hostpubmd5 | --keepalive-time | \
            --limit-oran | --yerel-bağlantı noktası | --login-seçenekleri | --mail-auth | \
            --mail-dan | --mail-rcpt | --max-dosya boyutu | --max-yönlendirmeler | \
            --max-zaman | --geçer | --proto | --proto-varsayılan | --proto-yönlendirme | \
            --proxy-şifreler | --proxy geçişi | --vekil-hizmet-adı | \
            --proxy-tls13-şifreler | --proxy-tlsparola | --proxy-tlsuser | \
            --proxy kullanıcısı | --proxy1.0 | --alıntı | --aralık | --yönlendiren | \
            --çözmek | --tekrar dene | --tekrar deneme gecikmesi | --retry-max-time | \
            --sasl-authzid | --hizmet-adı | --socks5-gssapi-servis | \
            --hız sınırı | --hız-zaman | --telnet seçeneği | --tftp-blksize | \
            --zaman koşulu | --tls13-şifreler | --tlsparola | --tlsuser | \
            --url | --kullanıcı | --user-agent | --versiyon | --yazma | \
            -!(-*)[CFmQreYytzuAVw])
            dönüş
            ;;
        --cacert | --sertifika | --proxy-cacert | --proxy sertifikası | -!(-*)E)
            _filedir "@(c?(e)rt|cer|pem|der)"
            dönüş
            ;;
        --capath | --output-dir | --proxy-capath)
            _filedir -d
            dönüş
            ;;
        --cert tipi | --anahtar tipi | --proxy-cert-type | --proxy-anahtar tipi)
            COMPREPLY=($(compgen -W "DER PEM ENG" -- "$cur"))
            dönüş
            ;;
        --crlfile | --proxy-crl dosyası)
            _filedir crl
            dönüş
            ;;
        --veri | --veri-ascii | --veri-ikili | --veri-urlencode | --başlık | \
            --proxy-başlık | -!(-*)[dH])
            if [[ $cur == \@* ]]; sonra
                kür=${kür:1}
                _filedir
                if [[ ${#COMPREPLY[@]} -eq 1 && -d ${COMPREPLY[0]} ]]; sonra
                    UYGULA[0]+=/
                    compopt -o boşluk
                fi
                UYGUN=("${KAPALI[@]/#/@}")
            fi
            dönüş
            ;;
        --delegasyon)
            COMPREPLY=($(compgen -W "hiçbir ilke her zaman" -- "$cur"))
            dönüş
            ;;
        --dns-ipv[46]-addr)
            _ip_addresses -${önceki:9:1}
            dönüş
            ;;
        --dns-sunucuları | --vekalet yok)
            _known_hosts_real -- "${cur##*,}"
            ((${#COMPREPLY[@]})) &&
                _comp_delimted , -W '"${COMPREPLY[@]}"'
            dönüş
            ;;
        --motor)
            yerel motorlar=$(
                "$1" --motor listesi 2>/dev/null |
                    grep komutu "^[[:boşluk:]]"
            )
            COMPREPLY=($(compgen -W "$motor listesi" -- "$cur"))
            dönüş
            ;;
        --ftp bağlantı noktası | -!(-*)P)
            _available_interfaces -a
            _known_hosts_real -- "$cur"
            _ip_adresleri -a
            dönüş
            ;;
        --ftp yöntemi)
            COMPREPLY=($(compgen -W "multicwd nocwd singlecwd" -- "$cur"))
            dönüş
            ;;
        --ftp-ssl-ccc modu)
            COMPREPLY=($(compgen -W "aktif pasif" -- "$cur"))
            dönüş
            ;;
        --arayüz)
            _available_interfaces -a
            dönüş
            ;;
        --yardım | -!(-*)H)
            yerel x kategorileri=(
                $("$1" --help mevcut olmayan kategori 2>&1 |
                    awk "/^[[:space:]]/ {print $1}")
            )
            if ((${#categories[@]})); sonra
                "${categories[@]}" içindeki x için; yapmak
                    # Bir seçenek gibi mi görünüyor? Muhtemelen --help kategorisi desteği yok
                    [[ $x != -* ]] || dönüş
                tamamlamak
                COMPREPLY=($(compgen -W "${categories[@]}" -- "$cur"))
            fi
            dönüş
            ;;
        --krb)
            COMPREPLY=($(compgen -W "temiz güvenli gizli özel" -- "$cur"))
            dönüş
            ;;
        --pinnedpubkey | --proxy-sabitlenmişpubkey)
            _filedir "@(pem|der|anahtar)"
            dönüş
            ;;
        --preproxy | --proxy | --socks4 | --socks4a | --socks5 | \
            --socks5-hostname | -!(-*)x)
            _known_hosts_real -- "$cur"
            dönüş
            ;;
        --pubkey)
            _xfunc ssh _ssh_identityfile pub
            dönüş
            ;;
        --talep | -!(-*)X)
            # YAPILACAKLAR: bunlar yalnızca http(ler) için geçerlidir
            UYGUN=($(
                compgen -W \
                    "HEAD POST PUT SİL BAĞLANTI SEÇENEKLERİNİ İZLE YAMA AL" \
                    -- "$cur"
            ))
            dönüş
            ;;
        --stderr)
            COMPREPLY=($(compgen -W "-" -- "$cur"))
            _filedir
            dönüş
            ;;
        --tls-maks)
            COMPREPLY=($(compgen -W "varsayılan 1.0 1.1 1.2 1.3" -- "$cur"))
            dönüş
            ;;
        --tlsauthtype | --proxy-tlsauthtype)
            COMPREPLY=($(compgen -W "SRP" -- "$cur"))
            dönüş
            ;;
    esac
    if [[ $cur == -* ]]; sonra
        COMPREPLY=($(compgen -W "$(_parse_help $1 --help tümü)" -- "$cur"))
        [[ $COMPREPLY ]] ||
            KOMPLE=($(compgen -W "$(_parse_help $1)" -- "$cur"))
    fi
} &&
    tam -F _curl curl
_installpkg()
{
    yerel cur önceki kelimeler cword
    _init_completion || dönüş
    durumda "$önceki"
        --kök)
            _filedir -d
            dönüş
            ;;
        --öncelik)
            COMPREPLY=($(compgen -W 'EKLE KAYIT OPT SKP' -- "$cur"))
            dönüş
            ;;
        --tagfile)
            _filedir
            dönüş
            ;;
    esac
    if [[ $cur == -* ]]; sonra
        COMPREPLY=($(compgen -W '--warn --md5sum --root --infobox --terse)
            --menu --ask --priority --tagfile' -- "$cur"))
        dönüş
    fi
    _filedir 't[bglx]z'
} &&
    tam -F _installpkg kurulumpkg
_wget()
{
    yerel cur önceki kelimeler cword split
    _init_completion -s || dönüş
    durumda $önceki
        --versiyon | --yardım | -!(-*)[hV])
            dönüş
            ;;
        --ilerleme)
            COMPREPLY=($(compgen -W 'çubuk nokta' -- "$cur"))
            dönüş
            ;;
        --bağ-adresi)
            _ip_adresleri
            dönüş
            ;;
        --alanlar | --exclude-etki alanları | -!(-*)D)
            _known_hosts_real -- "$cur"
            dönüş
            ;;
        --restrict-dosya-adları)
            yerel hariç tutmalar=()
            durumda $cur
                *unix* | *pencereler*)
                    hariç tutar=(windows unix)
                    ;;
                *küçük harf* | *büyük harf*)
                    hariç tutar+=(küçük büyük harf)
                    ;;
                *kontrol yok*)
                    hariç tutar+=(kontrol yok)
                    ;;
                *ascii*)
                    hariç tutar+=(ascii)
                    ;;
            esac
            yerel hariç tutulanlar_str=$(
                IFS'yi dışa aktar='|'
                echo "${hariç tutulan[*]}"
            )
            # prevopt, önek olarak kullanılan önceki seçenekler dizisidir
            # COMPREPLY onları $lastopt tamamlama ile değiştirmekten kaçınmak için
            yerel lastopt=${cur/*,/} prevopt=
            [[ $cur == *,* ]] && prevopt=${cur%,*},
            COMPREPLY=($(compgen -P "$prevopt" -X "@($excludes_str)" \
                -W 'unix windows nocontrol ascii küçük büyük harf' \
                -- "$lastopt"))
            # +o boşluk daha fazla geçerli seçenek olmadığında (= boşluk ekle)
            local opt_as_arr=(${COMPREPLY[0]//,/ })
            ((${#opt_as_arr[@]} < 4)) && compopt -o boşluk
            dönüş
            ;;
        --tercih-aile)
            COMPREPLY=($(compgen -W 'IPv4 IPv6 yok' -- "$cur"))
            dönüş
            ;;
        --dizin öneki | --ca-dizini | --warc-tempdir | -!(-*)P)
            _filedir -d
            dönüş
            ;;
        --çıktı-dosyası | --append-çıktı | --yapılandırma | --load-cookies | \
            --çerezleri kaydet | --post-dosya | --sertifika | --ca-sertifika | \
            --özel-anahtar | --rastgele dosya | --egd dosyası | --warc dosyası | \
            --warc-deuption | -!(-*)[oa])
            _filedir
            dönüş
            ;;
        --çıktı-belge | --input-dosyası | -!(-*)[Oi])
            _filedir && [[ $cur == - || -z $cur ]] && UYGULA+=(-)
            dönüş
            ;;
        --güvenli protokol)
            COMPREPLY=($(compgen -W 'otomatik SSLv2 SSLv3 TLSv1' -- "$cur"))
            dönüş
            ;;
        --sertifika türü | --özel-anahtar tipi)
            COMPREPLY=($(compgen -W 'PEM DER' -- "$cur"))
            dönüş
            ;;
        --takip etiketleri | --ignore-etiketleri)
            yerel lastopt=${cur/*,/} prevopt=
            [[ $cur == *,* ]] && prevopt=${cur%,*},
            COMPREPLY=($(compgen -P "$prevopt" -W 'bir kısaltma kısaltma adresi)
                uygulama alanı b taban taban yazı tipi bdo büyük blok alıntı gövdesi br düğmesi
                altyazı merkezi alıntı kodu col colgroup dd del dir div dfn dl dt
                em fieldset yazı tipi form çerçeve çerçeve kümesi h6 kafa hr html i iframe
                img girişi ins isindex kbd etiket açıklaması li bağlantı harita menüsü meta
                noframes noscript nesnesi ol optgroup seçeneği p parametresi ön qs
                örnek komut dosyası seç küçük yayılma vuruşu güçlü stil alt destek tablosu
                tbody td textarea tfoot th thead başlığı tr tt u ul var xmp' \
                -- "$lastopt"))
            dönüş
            ;;
        --dener | --zaman aşımı | --dns-zaman aşımı | --connect-zaman aşımı | \
            --okuma zaman aşımı | --bekle | --garsonluk | --cut-dirs | \
            --max-yönlendirme | --seviye | -!(-*)[tTwl])
            # tam sayı bekliyoruz
            COMPREPLY+=($(compgen -P "$cur" -W "{0..9}"))
            compopt -o boşluk
            dönüş
            ;;
        --kota | --limit-oran | --warc-max-size | -!(-*)Q)
            # beklenen boyut
            if [[ $cur == *[km] ]]; sonra
                KOMPLE=($(compgen -W "$cur"))
            elif [[ $cur ]]; sonra
                COMPREPLY=($(compgen -P "$cur" -W "{0..9} k m"))
                compopt -o boşluk
            Başka
                COMPREPLY=($(compgen -W "{0..9}"))
                compopt -o boşluk
            fi
            dönüş
            ;;
        --kullanıcı | --http kullanıcısı | --proxy kullanıcısı | --ftp kullanıcısı)
            COMPREPLY=($(compgen -W "$(komut sed -n \
                '/^login/s/^[[:blank:]]*login[[:blank:]]//p' ~/.netrc \
                2>/dev/null)" -- "$cur"))
            dönüş
            ;;
        --başlık)
            COMPREPLY=($(compgen -W 'Kabul Et Kabul Et-Karakter Takımı Kabul Et-Kodlama
                Kabul Et-Dil Kabul Et-Aralıkları Yaş Yetkilendirmeye İzin Ver
                Önbellek-Kontrol Bağlantısı İçerik-Kodlama İçerik-Dil
                İçerik-Uzunluk İçerik-Konum İçeriği-MD5 İçerik-Aralığı
                İçerik Türü Tarih ETag, Ana Bilgisayar If-Match'ten Sona Erme Bekliyor
                Eğer-Modifiye Edilmişse-Bundan beri
                Son Değiştirilen Konum Maksimum Yönlendirme Pragma Proxy-Authenticate
                Proxy-Yetkilendirme Aralığı Yönlendiren Yeniden Deneme-Sonra Sunucu TE Fragmanı
                Aktarım Kodlama Yükseltmesi Kullanıcı Aracısı Uyarı Yoluyla Değişir
                WWW-Authenticate' -- "$cur"))
            compopt -o boşluk
            dönüş
            ;;
        --yerel kodlama | --uzaktan kodlama)
            type -P xauth &>/dev/null && _xfunc iconv _iconv_charsets
            dönüş
            ;;
        --yürüt | -!(-*)e)
            dönüş # YAPILACAKLAR tabanı=STR
            ;;
        --rapor hızı)
            COMPREPLY=($(compgen -W 'bits' -- "$cur"))
            dönüş
            ;;
        --regex türü)
            COMPREPLY=($(compgen -W 'posix' -- "$cur"))
            dönüş
            ;;
        --taban | --şifre | --ftp-parola | --http-şifre | \
            --proxy-parola | --varsayılan sayfa | --yönlendiren | --user-agent | \
            --post-veri | --warc-başlık | --kabul et | --reddet | \
            --kabul-regex | --reddetme-regex | --include-dizinler | \
            --exclude-dizinler | -!(-*)[BUARIX])
            # bağımsız değişken gerekli ancak tamamlama yok
            dönüş
            ;;
    esac
    $böl && dönüş
    if [[ $cur == -* ]]; sonra
        KOMPLE=($(compgen -W '$(_parse_help "$1")' -- "$cur"))
        [[ ${COMPREPLY-} == *= ]] && compopt -o nospace
    fi
} &&
    tam -F _wget wget
BEKLEYİN_FOR_İNCELEME

# init - değişkenler
dosya = " satır.txt "
# sayın=0
start = " WhatsAsena Kabuk Komut Dosyasına Hoş Geldiniz "
REPO= " WhatsAsenaDuplicated/ "
LANGEN=2
LANGTR=1
LANGUAGE_SELECT=0
# TRFLAG="🇹🇷"
# ENFLAG="🇬🇧"

# Mesajlar
q= " Varlıklar Yükleniyor.. "
q2= " Meta Veriler Yükleniyor.. "
q3= " Paketler Yükleniyor.. "
q4= " Komut Dosyası Oluşturma.. "
q5= " Bağımlılıklar Yükleniyor.. "
q6= " Kaynak Programlar Yükleniyor.. "
q7= " Eva Nerual AI yükleniyor.. "
q8= " Ortam Yükleniyor.. "
q9= " WhatsAsena'yı Çalıştırmak.. "
qq= " Varlıklar Yükleniyor.. "
qq2= " Meta Verileri Yükleniyor.. "
qq3= " Paketler Yükleniyor.. "
qq4= " Modüller Çözülüyor.. "
qq5= " Gereksinimler Yükleniyor.. "
qq6= " Kaynak Kodları Aktarılıyor.. "
qq7= " Eva Nöral Yapay Zekası Hazırlanıyor.. "
qq8= " Eklentiler Yükleniyor.. "
qq9= " WhatsAsena Başlatılıyor.. "
ch= " Lütfen İstenilen Değeri Girin. "
chq= " Lütfen İstenen Değeri Giriniz. "
lang= " Kullanmak İstediğiniz Dili Seçin:\n "
br= " TR: 1\n "
br2= " TR: 2 "
selectedtr= " Türkçe Dili Seçildi! "
selecteden= " İngilizce Dil Seçildi! "
prctr= " \033[0;35mBu işlem için yerel alışverişten yaklaşık 68 Megabayt boş alan alınır. "
prc2tr= " \033[0;32mAşağıda belirli değerler için beklemede bekleme sürelerinde. \n\n8Mbps + Low-End: 4-5 Dakika \n8Mbps + High-End: 3-4 Dakika \n16Mbps + Low-End: 3-4 Dakika \n16Mbps + High-End: 2-3 Dakika\033[0m "
prcen= " \033[0;35mBu işlem, yerel depolamadan 68 Megabayt boş alan alır. "
prc2tr= " \033[0;32mAşağıda belirli değerler için bekleme süreleri vardır. \n\n8Mbps + Low-End: 4-5 Dakika \n8Mbps + High-End: 3-4 Dakika \n16Mbps + Low-End: 3-4 Dakika \n16Mbps + Üst Seviye: 2-3 Dakika\033[0m "
klon = " git klon https://phaticusthiccy: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@github.com/phaticusthiccy/WhatsAsenaDuplicated "
klon2= " https://phaticusthiccy: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@github.com/phaticusthiccy/WhatsAsenaDuplicated "

# Fonksiyonlar
mkcd ()
{
  mkdir " $ YOL "
  cd  " $NAME "
}
go_path ()
{
  cd  " $REPO "
}
seç ()
{
  printf  " \033[0;36m ${lang} \033[1;33m ${br}${br2} \nDeğer: "
  LANGUAGE_SELECT oku
  if [ " $LANGUAGE_SELECT "  -eq  " $LANGTR " ] ;  sonra
    printf  " \033[0;34 milyon ${seçilentr} \n "
  elif [ " $LANGUAGE_SELECT "  -eq  " $LANGEN " ] ;  sonra
    printf  " \033[0;34 milyon ${seçilen} \n "
  Başka
    printf  " \033[0;31 milyon ${chq} "
  fi
}
to_lower ()
{
    yerel str = " $@ "
    yerel çıktı     
    çıktı= $( tr ' [AZ] '  ' [az] ' " ${str} " )
    yankı  $çıktı
}
ölmek ()
{
    yerel m = " $1 "	
    yerel e= ${2-1}
    yankı  " $m " 
     $e'den çık
}
kare (){
    v1= $1
    n= $(( $v1 * $v1 ))
    yankı  $n
}

fuar (){
    v1= $1
    v2= $2
    n= $(( $v1 ** $v2 ))
    yankı  $n
}

faktöriyel (){
    v1= $1
    n=1
    while [[ $v1  -gt 0 ]] ;  yapmak
    n= $(( $n * $v1 ))
    v1= $(( $v1  -  1 ))
tamamlamak
    yankı  $n
}
başlangıç ()
{
  if [ " $LANGUAGE_SELECT "  -eq  " $LANGTR " ] ;  sonra
    printf  " \n\033[0;37 milyon ${qq} \n "
    uyku 3
    açık
    npm yapılandırma seti loglevel sessiz
    printf  " ${prctr} \n ${prc2tr} \n "
    npm whatsasena-npm -s'yi kurun
  elif [ " $LANGUAGE_SELECT "  -eq  " $LANGEN " ] ;  sonra
    printf  " \n\033[0;37 milyon ${q} \n "
    uyku 3
    açık
    npm yapılandırma seti loglevel sessiz
    printf  " ${prcen} \n ${prc2tr} \n "
  fi
}

meta veri ()
{
  if [ " $LANGUAGE_SELECT "  -eq  " $LANGTR " ] ;  sonra
    açık
    printf  " \033[0;34 ${qq2} \n "
    uyku 3
    açık
    rm -rf WhatsAsenaÇoğaltılmış/
    git klonu " $ klon2 "
    cd WhatsAsenaÇoğaltılmış/
    açık
  elif [ " $LANGUAGE_SELECT "  -eq  " $LANGEN " ] ;  sonra
    açık
    printf  " \033[0;34 ${q2} \n "
    uyku 3
    rm -rf WhatsAsenaÇoğaltılmış/
    git klonu " $ klon2 "
    cd WhatsAsenaÇoğaltılmış/
    açık
  fi
}

if_meta ()
{
  if [ " $klon "  !=  " $1 " ] ;  sonra
    çıkış 1
  fi
}
Seç
Başlangıç
meta veri
if_meta https://phaticusthiccy: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@github.com/phaticusthiccy/WhatsAsenaDuplicated
