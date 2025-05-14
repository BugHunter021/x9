package main

import (
    "bufio"
    "fmt"
    "math"
    "net/url"
    "os"
    "strings"
    "sync"

    "github.com/projectdiscovery/goflags"
    "github.com/projectdiscovery/gologger"
    "github.com/projectdiscovery/gologger/levels"
    fileUtil "github.com/projectdiscovery/utils/file"
    sliceUtil "github.com/projectdiscovery/utils/slice"
)

type Options struct {
    list               string
    parameters         string
    chunk              int
    values             goflags.StringSlice
    generationStrategy goflags.StringSlice
    valueStrategy      string
    output             string
    doubleEncode       bool
    silent             bool // پرچم جدید برای غیرفعال کردن گزارش
}

var (
    options *Options
    stats   Stats
)

type Stats struct {
    TotalUrls        int   // تعداد کل URLهای دریافتی
    ValidUrls        int   // تعداد URLهای معتبر
    InvalidUrls      int   // تعداد URLهای نامعتبر
    UrlsWithOutput   int   // تعداد URLهایی که خروجی تولید کردن
    TotalOutputUrls  int64 // تعداد کل URLهای خروجی
    mu               sync.Mutex // برای thread-safety در به‌روزرسانی آمار
}

func main() {
    options = ParseOptions()

    // باز کردن فایل خروجی (یا استفاده از stdout)
    var outputFile *os.File
    if options.output != "" {
        var err error
        outputFile, err = os.OpenFile(options.output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
        if err != nil {
            gologger.Fatal().Msg(err.Error())
        }
        defer outputFile.Close()
    } else {
        outputFile = os.Stdout
    }

    // خواندن پارامترها
    params := getParams()

    // پردازش URLها به‌صورت استریم
    urls := getUrlsStream()
    for singleUrl := range urls {
        stats.mu.Lock()
        stats.TotalUrls++
        stats.mu.Unlock()

        // شمارش URLهای معتبر/نامعتبر و خروجی‌ها تو توابع استراتژی انجام می‌شه
        var producedOutput bool
        if sliceUtil.Contains(options.generationStrategy, "normal") {
            if normalStrat(singleUrl, params, outputFile) {
                producedOutput = true
            }
        }
        if sliceUtil.Contains(options.generationStrategy, "combine") {
            if combineStrat(singleUrl, outputFile) {
                producedOutput = true
            }
        }
        if sliceUtil.Contains(options.generationStrategy, "ignore") {
            if ignoreStrat(singleUrl, params, outputFile) {
                producedOutput = true
            }
        }
        if producedOutput {
            stats.mu.Lock()
            stats.UrlsWithOutput++
            stats.mu.Unlock()
        }
    }

    // چاپ گزارش نهایی (فقط اگه silent غیرفعال باشه)
    printReport()
}

func printReport() {
    if options.silent {
        return // اگه silent فعال باشه، گزارش چاپ نمی‌شه
    }
    gologger.Info().Msg("--- Processing Report ---")
    gologger.Info().Msgf("Total URLs processed: %d", stats.TotalUrls)
    gologger.Info().Msgf("Valid URLs: %d", stats.ValidUrls)
    gologger.Info().Msgf("Invalid URLs: %d", stats.InvalidUrls)
    gologger.Info().Msgf("URLs that produced output: %d", stats.UrlsWithOutput)
    gologger.Info().Msgf("Total output URLs generated: %d", stats.TotalOutputUrls)
    gologger.Info().Msg("-----------------------")
}

func ParseOptions() *Options {
    options := &Options{}
    gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

    flags := goflags.NewFlagSet()
    flags.SetDescription("A tool designed for URL modification with specific modes to manipulate parameters and their values")

    flags.StringVarP(&options.list, "list", "l", "", "List of URLS to edit (stdin could be used alternatively)")
    flags.StringVarP(&options.parameters, "parameters", "p", "", "Parameter wordlist")
    flags.IntVarP(&options.chunk, "chunk", "c", 15, "Number of parameters in each URL")
    flags.StringSliceVarP(&options.values, "value", "v", nil, "Value for the parameters", goflags.StringSliceOptions)

    generationStrategyHelp := `
    Select the mode strategy from the available choices:
                    normal:  Remove all parameters and put the wordlist
                    combine: Pitchfork combine on the existing parameters
                    ignore:  Don't touch the URL and append the parameters to the URL
                `
    flags.StringSliceVarP(&options.generationStrategy, "generate-strategy", "gs", nil, generationStrategyHelp, goflags.CommaSeparatedStringSliceOptions)

    valueStrategyHelp := `Select the strategy from the available choices:
                    replace: Replace the current URL values with the given values
                    suffix:  Append the value to the end of the parameters
                `
    flags.StringVarP(&options.valueStrategy, "value-strategy", "vs", "suffix", valueStrategyHelp)

    flags.StringVarP(&options.output, "output", "o", "", "File to write output results")
    flags.BoolVarP(&options.doubleEncode, "double-encode", "de", false, "Double encode the values")
    flags.BoolVarP(&options.silent, "silent", "s", false, "Suppress processing report output") // پرچم جدید silent

    if err := flags.Parse(); err != nil {
        gologger.Fatal().Msg(err.Error())
    }

    if err := options.validateOptions(); err != nil {
        gologger.Fatal().Msg(err.Error())
    }

    return options
}

func (options *Options) validateOptions() error {
    if !fileUtil.HasStdin() && options.list == "" {
        return fmt.Errorf("No URLs were given")
    }
    if fileUtil.FileExists(options.output) && options.output != "" {
        return fmt.Errorf("Output file already exists")
    }
    if !fileUtil.FileExists(options.list) && options.list != "" {
        return fmt.Errorf("URL list does not exist")
    }
    if options.parameters == "" && !(len(options.generationStrategy) == 1 && sliceUtil.Contains(options.generationStrategy, "combine")) {
        return fmt.Errorf("Parameter wordlist file is not given")
    }
    if !fileUtil.FileExists(options.parameters) && options.parameters != "" {
        return fmt.Errorf("Parameter wordlist file does not exist")
    }
    if options.valueStrategy != "replace" && options.valueStrategy != "suffix" {
        return fmt.Errorf("Value strategy is not valid")
    }
    if !sliceUtil.Contains(options.generationStrategy, "combine") &&
        !sliceUtil.Contains(options.generationStrategy, "ignore") &&
        !sliceUtil.Contains(options.generationStrategy, "normal") {
        return fmt.Errorf("Generation strategy is not valid")
    }
    if options.values == nil {
        return fmt.Errorf("No values are given")
    }
    return nil
}

func getParams() []string {
    params := []string{}
    if len(options.generationStrategy) == 1 && sliceUtil.Contains(options.generationStrategy, "combine") {
        return params
    }
    ch, err := fileUtil.ReadFile(options.parameters)
    if err != nil {
        gologger.Fatal().Msg(err.Error())
    }
    for param := range ch {
        params = append(params, param)
    }
    return params
}

func getUrlsStream() chan string {
    urls := make(chan string)
    go func() {
        defer close(urls)
        if options.list != "" {
            ch, err := fileUtil.ReadFile(options.list)
            if err != nil {
                gologger.Fatal().Msg(err.Error())
            }
            for url := range ch {
                urls <- url
            }
        } else if fileUtil.HasStdin() {
            scanner := bufio.NewScanner(os.Stdin)
            for scanner.Scan() {
                urls <- strings.TrimSpace(scanner.Text())
            }
            if err := scanner.Err(); err != nil {
                gologger.Fatal().Msg(err.Error())
            }
        }
    }()
    return urls
}

func combineStrat(singleUrl string, outputFile *os.File) bool {
    // parse each url
    parsedUrl, err := url.Parse(singleUrl)
    if err != nil {
        stats.mu.Lock()
        stats.InvalidUrls++
        stats.mu.Unlock()
        return false
    }
    queryParams := parsedUrl.Query()
    numOfOldParams := len(queryParams)
    if numOfOldParams == 0 {
        stats.mu.Lock()
        stats.ValidUrls++
        stats.mu.Unlock()
        return false // اگه پارامتری نباشه، خروجی تولید نمی‌کنه
    }

    // فقط از اولین مقدار استفاده می‌کنیم
    value := options.values[0]
    if options.doubleEncode {
        value = url.QueryEscape(value)
    }

    // تغییر هر پارامتر به‌صورت جداگانه
    outputCount := 0
    for key := range queryParams {
        newQueryParams := url.Values{}
        for k := range queryParams {
            newQueryParams.Set(k, queryParams.Get(k))
        }
        if options.valueStrategy == "replace" {
            newQueryParams.Set(key, value)
        } else {
            newQueryParams.Set(key, queryParams.Get(key)+value)
        }
        parsedUrl.RawQuery = newQueryParams.Encode()
        fmt.Fprintln(outputFile, parsedUrl.String())
        outputCount++
    }

    stats.mu.Lock()
    stats.ValidUrls++
    stats.TotalOutputUrls += int64(outputCount)
    stats.mu.Unlock()
    return true
}

func ignoreStrat(singleUrl string, params []string, outputFile *os.File) bool {
    // parse each url
    parsedUrl, err := url.Parse(singleUrl)
    if err != nil {
        stats.mu.Lock()
        stats.InvalidUrls++
        stats.mu.Unlock()
        return false
    }
    queryParams := parsedUrl.Query()

    // فقط پارامترهای جدید
    existingKeys := make(map[string]struct{}, len(queryParams))
    for key := range queryParams {
        existingKeys[key] = struct{}{}
    }
    newKeys := make([]string, 0, len(params))
    for _, p := range params {
        if _, exists := existingKeys[p]; !exists {
            newKeys = append(newKeys, p)
        }
    }

    numOfOldParams := len(queryParams)
    chunkSize := options.chunk - numOfOldParams
    if chunkSize <= 0 {
        chunkSize = 1
    }
    numIterations := int(math.Ceil(float64(len(newKeys)) / float64(chunkSize)))

    outputCount := 0
    for _, singleValue := range options.values {
        value := singleValue
        if options.doubleEncode {
            value = url.QueryEscape(value)
        }

        for i := 0; i < numIterations; i++ {
            newQueryParams := url.Values{}
            for key := range queryParams {
                newQueryParams.Set(key, queryParams.Get(key))
            }

            start := i * chunkSize
            end := start + chunkSize
            if end > len(newKeys) {
                end = len(newKeys)
            }
            for _, param := range newKeys[start:end] {
                newQueryParams.Set(param, value)
            }

            parsedUrl.RawQuery = newQueryParams.Encode()
            fmt.Fprintln(outputFile, parsedUrl.String())
            outputCount++
        }
    }

    stats.mu.Lock()
    stats.ValidUrls++
    if outputCount > 0 {
        stats.TotalOutputUrls += int64(outputCount)
    }
    stats.mu.Unlock()
    return outputCount > 0
}

func normalStrat(singleUrl string, params []string, outputFile *os.File) bool {
    // parse each url
    parsedUrl, err := url.Parse(singleUrl)
    if err != nil {
        stats.mu.Lock()
        stats.InvalidUrls++
        stats.mu.Unlock()
        return false
    }

    // فقط پارامترهای جدید
    existingKeys := make(map[string]struct{}, len(parsedUrl.Query()))
    for key := range parsedUrl.Query() {
        existingKeys[key] = struct{}{}
    }
    newKeys := make([]string, 0, len(params))
    for _, p := range params {
        if _, exists := existingKeys[p]; !exists {
            newKeys = append(newKeys, p)
        }
    }

    numIterations := int(math.Ceil(float64(len(newKeys)) / float64(options.chunk)))

    outputCount := 0
    for _, singleValue := range options.values {
        value := singleValue
        if options.doubleEncode {
            value = url.QueryEscape(value)
        }

        for i := 0; i < numIterations; i++ {
            newQueryParams := url.Values{}
            start := i * options.chunk
            end := start + options.chunk
            if end > len(newKeys) {
                end = len(newKeys)
            }
            for _, param := range newKeys[start:end] {
                newQueryParams.Set(param, value)
            }

            parsedUrl.RawQuery = newQueryParams.Encode()
            fmt.Fprintln(outputFile, parsedUrl.String())
            outputCount++
        }
    }

    stats.mu.Lock()
    stats.ValidUrls++
    if outputCount > 0 {
        stats.TotalOutputUrls += int64(outputCount)
    }
    stats.mu.Unlock()
    return outputCount > 0
}

func newParamsOnlyStrat(singleUrl string, params []string, outputFile *os.File) bool {
    // parse each url
    parsedUrl, err := url.Parse(singleUrl)
    if err != nil {
        stats.mu.Lock()
        stats.InvalidUrls++
        stats.mu.Unlock()
        return false
    }

    // URL پایه
    baseUrl := parsedUrl.Scheme + "://" + parsedUrl.Host + parsedUrl.Path
    parsedUrl, err = url.Parse(baseUrl)
    if err != nil {
        stats.mu.Lock()
        stats.InvalidUrls++
        stats.mu.Unlock()
        return false
    }

    numIterations := int(math.Ceil(float64(len(params)) / float64(options.chunk)))

    outputCount := 0
    for _, singleValue := range options.values {
        value := singleValue
        if options.doubleEncode {
            value = url.QueryEscape(value)
        }

        for i := 0; i < numIterations; i++ {
            newQueryParams := url.Values{}
            start := i * options.chunk
            end := start + options.chunk
            if end > len(params) {
                end = len(params)
            }
            for _, param := range params[start:end] {
                newQueryParams.Set(param, value)
            }

            parsedUrl.RawQuery = newQueryParams.Encode()
            fmt.Fprintln(outputFile, parsedUrl.String())
            outputCount++
        }
    }

    stats.mu.Lock()
    stats.ValidUrls++
    if outputCount > 0 {
        stats.TotalOutputUrls += int64(outputCount)
    }
    stats.mu.Unlock()
    return outputCount > 0
}
