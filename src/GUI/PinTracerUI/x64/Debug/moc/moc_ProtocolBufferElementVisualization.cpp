/****************************************************************************
** Meta object code from reading C++ file 'ProtocolBufferElementVisualization.h'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.5.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../include/widgets/protocol/ProtocolBufferElementVisualization.h"
#include <QtCore/qmetatype.h>

#if __has_include(<QtCore/qtmochelpers.h>)
#include <QtCore/qtmochelpers.h>
#else
QT_BEGIN_MOC_NAMESPACE
#endif


#include <memory>

#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'ProtocolBufferElementVisualization.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.5.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
QT_WARNING_DISABLE_GCC("-Wuseless-cast")
namespace {

#ifdef QT_MOC_HAS_STRINGDATA
struct qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t {};
static constexpr auto qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS = QtMocHelpers::stringData(
    "ProtocolBufferElementVisualization",
    "onPointedByteHighlighButtonClicked",
    "",
    "byteOffset",
    "buttonRequestHighlightPointedToByte"
);
#else  // !QT_MOC_HAS_STRING_DATA
struct qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t {
    uint offsetsAndSizes[10];
    char stringdata0[35];
    char stringdata1[35];
    char stringdata2[1];
    char stringdata3[11];
    char stringdata4[36];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS = {
    {
        QT_MOC_LITERAL(0, 34),  // "ProtocolBufferElementVisualiz..."
        QT_MOC_LITERAL(35, 34),  // "onPointedByteHighlighButtonCl..."
        QT_MOC_LITERAL(70, 0),  // ""
        QT_MOC_LITERAL(71, 10),  // "byteOffset"
        QT_MOC_LITERAL(82, 35)   // "buttonRequestHighlightPointed..."
    },
    "ProtocolBufferElementVisualization",
    "onPointedByteHighlighButtonClicked",
    "",
    "byteOffset",
    "buttonRequestHighlightPointedToByte"
};
#undef QT_MOC_LITERAL
#endif // !QT_MOC_HAS_STRING_DATA
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_CLASSProtocolBufferElementVisualizationENDCLASS[] = {

 // content:
      11,       // revision
       0,       // classname
       0,    0, // classinfo
       2,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    1,   26,    2, 0x06,    1 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       4,    0,   29,    2, 0x08,    3 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    3,

 // slots: parameters
    QMetaType::Void,

       0        // eod
};

Q_CONSTINIT const QMetaObject ProtocolBufferElementVisualization::staticMetaObject = { {
    QMetaObject::SuperData::link<QWidget::staticMetaObject>(),
    qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS.offsetsAndSizes,
    qt_meta_data_CLASSProtocolBufferElementVisualizationENDCLASS,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<ProtocolBufferElementVisualization, std::true_type>,
        // method 'onPointedByteHighlighButtonClicked'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<int, std::false_type>,
        // method 'buttonRequestHighlightPointedToByte'
        QtPrivate::TypeAndForceComplete<void, std::false_type>
    >,
    nullptr
} };

void ProtocolBufferElementVisualization::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<ProtocolBufferElementVisualization *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->onPointedByteHighlighButtonClicked((*reinterpret_cast< std::add_pointer_t<int>>(_a[1]))); break;
        case 1: _t->buttonRequestHighlightPointedToByte(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ProtocolBufferElementVisualization::*)(int );
            if (_t _q_method = &ProtocolBufferElementVisualization::onPointedByteHighlighButtonClicked; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
    }
}

const QMetaObject *ProtocolBufferElementVisualization::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ProtocolBufferElementVisualization::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CLASSProtocolBufferElementVisualizationENDCLASS.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int ProtocolBufferElementVisualization::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 2)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 2)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 2;
    }
    return _id;
}

// SIGNAL 0
void ProtocolBufferElementVisualization::onPointedByteHighlighButtonClicked(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
