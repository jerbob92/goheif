package libde265

import "C"
import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/experimental/logging"
	"github.com/tetratelabs/wazero/imports/emscripten"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"image"
	"log"
	"os"
)

//go:embed libde265.wasm
var libde265Wasm []byte

type Decoder struct {
	ctx          uint64
	dataPointers []uint64
	hasImage     bool
	safeEncode   bool
}

var wazeroModule api.Module
var wazeroContext context.Context

func Init() {
	wazeroContext = context.WithValue(context.Background(), experimental.FunctionListenerFactoryKey{}, logging.NewLoggingListenerFactory(os.Stdout))
	wazeroContext = context.Background()
	runtime := wazero.NewRuntimeWithConfig(wazeroContext, wazero.NewRuntimeConfig())

	// Import WASI features.
	if _, err := wasi_snapshot_preview1.Instantiate(wazeroContext, runtime); err != nil {
		runtime.Close(wazeroContext)
		log.Fatal(fmt.Errorf("could not instantiate webassembly wasi_snapshot_preview1 module: %w", err))
	}

	if _, err := emscripten.Instantiate(wazeroContext, runtime); err != nil {
		runtime.Close(wazeroContext)
		log.Fatal(fmt.Errorf("could not instantiate webassembly emscripten module: %w", err))
	}

	compiledModule, err := runtime.CompileModule(wazeroContext, libde265Wasm)
	if err != nil {
		runtime.Close(wazeroContext)
		log.Fatal(fmt.Errorf("could not compile webassembly module: %w", err))
	}

	moduleConfig := wazero.NewModuleConfig().WithStartFunctions("_initialize")

	mod, err := runtime.InstantiateModule(wazeroContext, compiledModule, moduleConfig)
	if err != nil {
		log.Fatal(fmt.Errorf("could not instantiate webassembly module: %w", err))
	}

	wazeroModule = mod

	_, err = wazeroModule.ExportedFunction("de265_init").Call(wazeroContext)
	if err != nil {
		log.Fatal(fmt.Errorf("could not call de265_init: %w", err))
	}
}

func Fini() {
	_, err := wazeroModule.ExportedFunction("de265_free").Call(wazeroContext)
	if err != nil {
		log.Fatal(fmt.Errorf("could not call de265_free: %w", err))
	}
}

func NewDecoder(opts ...Option) (*Decoder, error) {
	res, err := wazeroModule.ExportedFunction("de265_new_decoder").Call(wazeroContext)
	if err != nil {
		log.Fatal(fmt.Errorf("could not call de265_new_decoder: %w", err))
	}
	p := res[0]
	if p == 0 {
		return nil, fmt.Errorf("Unable to create decoder")
	}

	dec := &Decoder{ctx: p, hasImage: false}
	for _, opt := range opts {
		opt(dec)
	}

	return dec, nil
}

type Option func(*Decoder)

func WithSafeEncoding(b bool) Option {
	return func(dec *Decoder) {
		dec.safeEncode = b
	}
}

func (dec *Decoder) Free() {
	dec.Reset()
	_, err := wazeroModule.ExportedFunction("de265_free_decoder").Call(wazeroContext, dec.ctx)
	if err != nil {
		log.Fatal(fmt.Errorf("could not call de265_free_decoder: %w", err))
	}

	dec.freeData()
}

func (dec *Decoder) Reset() {
	if dec.ctx != 0 && dec.hasImage {
		_, err := wazeroModule.ExportedFunction("de265_release_next_picture").Call(wazeroContext, dec.ctx)
		if err != nil {
			log.Fatal(fmt.Errorf("could not call de265_release_next_picture: %w", err))
		}
		dec.hasImage = false
	}

	_, err := wazeroModule.ExportedFunction("de265_reset").Call(wazeroContext, dec.ctx)
	if err != nil {
		log.Fatal(fmt.Errorf("could not call de265_reset: %w", err))
	}

	dec.freeData()
}

func (dec *Decoder) freeData() {
	if len(dec.dataPointers) > 0 {
		for i := range dec.dataPointers {
			err := dec.free(dec.dataPointers[i])
			if err != nil {
				log.Fatal(fmt.Errorf("could not call free: %w", err))
			}
		}
		dec.dataPointers = []uint64{}
	}
}

func (dec *Decoder) allocateData(size uint64) uint64 {
	dataPointer, err := dec.malloc(size)
	if err != nil {
		log.Fatal(fmt.Errorf("could not call malloc: %w", err))
	}
	dec.dataPointers = append(dec.dataPointers, dataPointer)
	return dataPointer
}

func (dec *Decoder) Push(data []byte) error {
	var pos int
	totalSize := len(data)
	dataPointer := dec.allocateData(uint64(totalSize))
	success := wazeroModule.Memory().Write(uint32(dataPointer), data)
	if !success {
		return errors.New("could not write away image data to memory")
	}

	for pos < totalSize {
		if pos+4 > totalSize {
			return fmt.Errorf("Invalid NAL data")
		}

		nalSize := uint32(data[pos])<<24 | uint32(data[pos+1])<<16 | uint32(data[pos+2])<<8 | uint32(data[pos+3])
		pos += 4

		if pos+int(nalSize) > totalSize {
			return fmt.Errorf("Invalid NAL size: %d", nalSize)
		}

		_, err := wazeroModule.ExportedFunction("de265_push_NAL").Call(wazeroContext, dec.ctx, dataPointer+uint64(pos), uint64(nalSize), 0, 0)
		if err != nil {
			return fmt.Errorf("could not call de265_push_NAL: %w", err)
		}

		pos += int(nalSize)
	}

	return nil
}

func (dec *Decoder) free(pointer uint64) error {
	_, err := wazeroModule.ExportedFunction("free").Call(wazeroContext, pointer)
	if err != nil {
		return fmt.Errorf("could not call free: %w", err)
	}

	return nil
}

func (dec *Decoder) malloc(size uint64) (uint64, error) {
	res, err := wazeroModule.ExportedFunction("malloc").Call(wazeroContext, size)
	if err != nil {
		return 0, fmt.Errorf("could not call malloc: %w", err)
	}

	return res[0], nil
}

func (dec *Decoder) intValue(pointer uint64) (int, error) {
	res, success := wazeroModule.Memory().ReadUint32Le(uint32(pointer))
	if !success {
		return 0, fmt.Errorf("could not read intValue form memory")
	}

	return int(res), nil
}

func (dec *Decoder) DecodeImage(data []byte) (image.Image, error) {
	if dec.hasImage {
		fmt.Printf("previous image may leak")
	}

	if len(data) > 0 {
		if err := dec.Push(data); err != nil {
			return nil, err
		}
	}

	res, err := wazeroModule.ExportedFunction("de265_flush_data").Call(wazeroContext, dec.ctx)
	if err != nil {
		return nil, fmt.Errorf("could not call de265_flush_data: %w", err)
	}

	if res[0] != 0 {
		return nil, fmt.Errorf("could not call de265_flush_data: error code %d", res[0])
	}

	morePointer, err := dec.malloc(4)
	if err != nil {
		return nil, err
	}
	defer dec.free(morePointer)

	for true {
		res, err = wazeroModule.ExportedFunction("de265_decode").Call(wazeroContext, dec.ctx, morePointer)
		if err != nil {
			return nil, fmt.Errorf("could not call de265_decode: %w", err)
		}

		if res[0] != 0 {
			return nil, fmt.Errorf("could not call de265_decode: %d", res[0])
		}

		for {
			res, err = wazeroModule.ExportedFunction("de265_get_warning").Call(wazeroContext, dec.ctx)
			if err != nil {
				return nil, fmt.Errorf("could not call de265_get_warning: %w", err)
			}

			warning := res[0]
			if warning == 0 {
				break
			}

			// @todo: get warning text
			fmt.Printf("warning: %d\n", warning)
			//fmt.Printf("warning: %v\n", C.GoString(C.de265_get_error_text(warning)))
		}

		res, err = wazeroModule.ExportedFunction("de265_get_next_picture").Call(wazeroContext, dec.ctx)
		if err != nil {
			return nil, fmt.Errorf("could not call de265_get_next_picture: %w", err)
		}

		img := res[0]
		if img != 0 {
			dec.hasImage = true // lazy release

			res, err = wazeroModule.ExportedFunction("de265_get_image_width").Call(wazeroContext, img, 0)
			if err != nil {
				return nil, fmt.Errorf("could not call de265_get_image_width: %w", err)
			}

			width := res[0]

			res, err = wazeroModule.ExportedFunction("de265_get_image_height").Call(wazeroContext, img, 0)
			if err != nil {
				return nil, fmt.Errorf("could not call de265_get_image_height: %w", err)
			}

			height := res[0]
			
			ystridePointer, err := dec.malloc(4)
			if err != nil {
				return nil, err
			}
			defer dec.free(ystridePointer)

			cstridePointer, err := dec.malloc(4)
			if err != nil {
				return nil, err
			}
			defer dec.free(cstridePointer)

			res, err = wazeroModule.ExportedFunction("de265_get_image_plane").Call(wazeroContext, img, 0, ystridePointer)
			if err != nil {
				return nil, fmt.Errorf("could not call de265_get_image_height: %w", err)
			}
			y := res[0]

			res, err = wazeroModule.ExportedFunction("de265_get_image_plane").Call(wazeroContext, img, 1, cstridePointer)
			if err != nil {
				return nil, fmt.Errorf("could not call de265_get_image_height: %w", err)
			}
			cb := res[0]

			res, err = wazeroModule.ExportedFunction("de265_get_image_height").Call(wazeroContext, img, 1)
			if err != nil {
				return nil, fmt.Errorf("could not call de265_get_image_height: %w", err)
			}
			cheight := res[0]

			res, err = wazeroModule.ExportedFunction("de265_get_image_plane").Call(wazeroContext, img, 2, cstridePointer)
			if err != nil {
				return nil, fmt.Errorf("could not call de265_get_image_height: %w", err)
			}
			cr := res[0]

			ystride, err := dec.intValue(ystridePointer)
			if err != nil {
				return nil, fmt.Errorf("could not read ystride value: %w", err)
			}

			cstride, err := dec.intValue(cstridePointer)
			if err != nil {
				return nil, fmt.Errorf("could not read cstride value: %w", err)
			}

			//			crh := C.de265_get_image_height(img, 2)

			// sanity check
			if int(height)*int(ystride) >= int(1<<30) {
				return nil, fmt.Errorf("image too big")
			}

			res, err = wazeroModule.ExportedFunction("de265_get_chroma_format").Call(wazeroContext, img)
			if err != nil {
				return nil, fmt.Errorf("could not call de265_get_chroma_format: %w", err)
			}
			chroma := res[0]

			var r image.YCbCrSubsampleRatio
			switch chroma {
			case 1:
				r = image.YCbCrSubsampleRatio420
			case 2:
				r = image.YCbCrSubsampleRatio422
			case 3:
				r = image.YCbCrSubsampleRatio444
			}
			ycc := &image.YCbCr{
				YStride:        int(ystride),
				CStride:        int(cstride),
				SubsampleRatio: r,
				Rect:           image.Rectangle{Min: image.Point{0, 0}, Max: image.Point{int(width), int(height)}},
			}

			yBytes, success := wazeroModule.Memory().Read(uint32(y), uint32(height)*uint32(ystride))
			if !success {
				return nil, fmt.Errorf("could not read yBytes from memory")
			}

			cbBytes, success := wazeroModule.Memory().Read(uint32(cb), uint32(cheight)*uint32(cstride))
			if !success {
				return nil, fmt.Errorf("could not read yBytes from memory")
			}

			crBytes, success := wazeroModule.Memory().Read(uint32(cr), uint32(cheight)*uint32(cstride))
			if !success {
				return nil, fmt.Errorf("could not read yBytes from memory")
			}

			ycc.Y = yBytes
			ycc.Cb = cbBytes
			ycc.Cr = crBytes

			//C.de265_release_next_picture(dec.ctx)

			return ycc, nil
		}

		more, err := dec.intValue(morePointer)
		if err != nil {
			return nil, fmt.Errorf("could not read more value: %w", err)
		}
		if more == 0 {
			break
		}
	}

	return nil, fmt.Errorf("No picture")
}
